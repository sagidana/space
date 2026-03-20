import datetime
import fcntl
import grp
import json
import os
import pwd
import re
import signal
import subprocess
from pathlib import Path

from .config import load as load_config


# ── group helpers ──────────────────────────────────────────────────────────────

def group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def create_group(name: str) -> None:
    subprocess.run(["groupadd", name], check=True)


def add_user_to_group(username: str, group: str) -> None:
    subprocess.run(["usermod", "-aG", group, username], check=True)


# ── iptables helpers ───────────────────────────────────────────────────────────

def get_wan_interface() -> str | None:
    """Return the interface used for the default route (the internet-facing NIC)."""
    result = subprocess.run(
        ["ip", "route", "get", "8.8.8.8"],
        capture_output=True, text=True,
    )
    m = re.search(r'\bdev\s+(\S+)', result.stdout)
    return m.group(1) if m else None


def _ipt(*args):
    subprocess.run(["iptables", *args], check=True)


def _ip6t(*args):
    subprocess.run(["ip6tables", *args], check=True)


# ── rule comment tags ──────────────────────────────────────────────────────────

_TAG_OUT_LO          = "space:output-lo"
_TAG_OUT_SUBNET      = "space:output-subnet"    # prefix; full tag is f"space:output-subnet-{subnet}"
_TAG_OUT_LINKLOCAL   = "space:output-linklocal"
_TAG_OUT_ESTABLISHED = "space:output-established"
_TAG_OUT_GID         = "space:output-gid"
_TAG_OUT_DROP        = "space:output-drop"
_TAG_FWD_WAN_DROP    = "space:forward-wan-drop"
_TAG_FWD_VETH_IN     = "space:forward-veth-in"
_TAG_FWD_VETH_OUT    = "space:forward-veth-out"
_TAG_NAT_MASQ        = "space:nat-masquerade"
_TAG_FWD_DOCKER_OUT  = "space:forward-docker-out"
_TAG_FWD_DOCKER_RET  = "space:forward-docker-return"


def _rule_exists(table: str, chain: str, comment_tag: str, ipv6: bool = False) -> bool:
    cmd = ["ip6tables" if ipv6 else "iptables", "-t", table, "-S", chain]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        needle = f'--comment "{comment_tag}"'
        return any(needle in line for line in result.stdout.splitlines())
    except Exception:
        return False


def _assert_rule_absent(table: str, chain: str, comment_tag: str, ipv6: bool = False, context: str = "") -> None:
    if _rule_exists(table, chain, comment_tag, ipv6=ipv6):
        where = f" (in {context})" if context else ""
        raise RuntimeError(
            f"rule '{comment_tag}' already exists in {table}/{chain}{where}. "
            "This means firewall rules were not cleaned up from a previous run. "
            "Run `sudo space panic` to recover."
        )


def _assert_rule_present(table: str, chain: str, comment_tag: str, ipv6: bool = False, context: str = "", warn_only: bool = False) -> bool:
    import sys
    if not _rule_exists(table, chain, comment_tag, ipv6=ipv6):
        msg = f"WARNING: expected rule '{comment_tag}' not found in {table}/{chain}"
        if context:
            msg += f" (in {context})"
        if warn_only:
            print(msg, file=sys.stderr)
            return False
        raise RuntimeError(msg)
    return True


def _chain_has_space_rules(chain: str, ipv6: bool = False) -> bool:
    cmd = ["ip6tables" if ipv6 else "iptables", "-t", "filter", "-S", chain]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return any("space:" in line for line in result.stdout.splitlines())
    except Exception:
        return False


def apply_rules(subnets: list[str], group: str) -> None:
    """Block all outbound internet traffic; allow loopback, LAN, and the internet group."""
    import sys

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    _ipt("-F", "OUTPUT")
    _ipt("-P", "OUTPUT", "ACCEPT")          # reset policy first

    if _chain_has_space_rules("OUTPUT"):
        print("WARNING: space rules remain in OUTPUT after flush (kernel issue)", file=sys.stderr)

    _ipt("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT",
         "-m", "comment", "--comment", _TAG_OUT_LO)

    for subnet in subnets:
        _ipt("-A", "OUTPUT", "-d", subnet, "-j", "ACCEPT",
             "-m", "comment", "--comment", f"space:output-subnet-{subnet}")

    _ipt("-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
         "-m", "comment", "--comment", _TAG_OUT_ESTABLISHED)
    _ipt("-A", "OUTPUT", "-m", "owner", "--gid-owner", group, "-j", "ACCEPT",
         "-m", "comment", "--comment", _TAG_OUT_GID)
    _ipt("-A", "OUTPUT", "-j", "DROP",
         "-m", "comment", "--comment", _TAG_OUT_DROP)

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    _ip6t("-F", "OUTPUT")
    _ip6t("-P", "OUTPUT", "ACCEPT")         # reset policy first

    if _chain_has_space_rules("OUTPUT", ipv6=True):
        print("WARNING: space rules remain in ip6tables OUTPUT after flush (kernel issue)", file=sys.stderr)

    _ip6t("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT",
          "-m", "comment", "--comment", _TAG_OUT_LO)
    # Allow link-local (needed for neighbour discovery / ICMPv6)
    _ip6t("-A", "OUTPUT", "-d", "fe80::/10", "-j", "ACCEPT",
          "-m", "comment", "--comment", _TAG_OUT_LINKLOCAL)

    _ip6t("-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
          "-m", "comment", "--comment", _TAG_OUT_ESTABLISHED)
    _ip6t("-A", "OUTPUT", "-m", "owner", "--gid-owner", group, "-j", "ACCEPT",
          "-m", "comment", "--comment", _TAG_OUT_GID)
    _ip6t("-A", "OUTPUT", "-j", "DROP",
          "-m", "comment", "--comment", _TAG_OUT_DROP)

    # ── FORWARD (containers / VMs routed through the host) ────────────────────
    # Insert at position 1 so our DROP precedes any ACCEPT rules added by Docker
    # or other tools. We match on the WAN interface (the default-route NIC) so
    # we block all forwarded internet traffic regardless of source subnet.
    wan = get_wan_interface()
    if wan:
        _assert_rule_absent("filter", "FORWARD", _TAG_FWD_WAN_DROP)
        _assert_rule_absent("filter", "FORWARD", _TAG_FWD_WAN_DROP, ipv6=True)
        _ipt("-I", "FORWARD", "1", "-o", wan, "-j", "DROP",
             "-m", "comment", "--comment", _TAG_FWD_WAN_DROP)
        _ip6t("-I", "FORWARD", "1", "-o", wan, "-j", "DROP",
              "-m", "comment", "--comment", _TAG_FWD_WAN_DROP)


def remove_rules() -> None:
    """Flush OUTPUT chain and restore ACCEPT policy."""
    _ipt("-F", "OUTPUT")
    _ipt("-P", "OUTPUT", "ACCEPT")
    _ip6t("-F", "OUTPUT")
    _ip6t("-P", "OUTPUT", "ACCEPT")

    # Remove the FORWARD DROP rule inserted by apply_rules. Use -D (delete by
    # spec) rather than flushing the whole chain — Docker and other tools may
    # have legitimate rules in FORWARD that we must not disturb.
    wan = get_wan_interface()
    if wan:
        _assert_rule_present("filter", "FORWARD", _TAG_FWD_WAN_DROP, warn_only=True,
                             context="remove_rules")
        subprocess.run(
            ["iptables", "-D", "FORWARD", "-o", wan, "-j", "DROP",
             "-m", "comment", "--comment", _TAG_FWD_WAN_DROP],
            capture_output=True,
        )
        _assert_rule_present("filter", "FORWARD", _TAG_FWD_WAN_DROP, ipv6=True,
                             warn_only=True, context="remove_rules")
        subprocess.run(
            ["ip6tables", "-D", "FORWARD", "-o", wan, "-j", "DROP",
             "-m", "comment", "--comment", _TAG_FWD_WAN_DROP],
            capture_output=True,
        )


def save_rules() -> None:
    """Persist rules via netfilter-persistent (iptables-persistent package)."""
    subprocess.run(["netfilter-persistent", "save"], check=True)


def is_blocking() -> bool:
    """Return True if a DROP rule exists in the OUTPUT or FORWARD chain (IPv4 or IPv6)."""
    for cmd in (
        ["iptables",  "-L", "OUTPUT",  "-n"],
        ["ip6tables", "-L", "OUTPUT",  "-n"],
        ["iptables",  "-L", "FORWARD", "-n"],
        ["ip6tables", "-L", "FORWARD", "-n"],
    ):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if "DROP" in result.stdout:
                return True
        except Exception:
            pass
    return False


def get_rules_text() -> str:
    parts = []
    for label, cmd in (
        ("iptables OUTPUT",          ["iptables",  "-L", "OUTPUT",      "-n", "-v", "--line-numbers"]),
        ("ip6tables OUTPUT",         ["ip6tables", "-L", "OUTPUT",      "-n", "-v", "--line-numbers"]),
        ("iptables FORWARD",         ["iptables",  "-L", "FORWARD",     "-n", "-v", "--line-numbers"]),
        ("ip6tables FORWARD",        ["ip6tables", "-L", "FORWARD",     "-n", "-v", "--line-numbers"]),
        ("iptables nat POSTROUTING", ["iptables",  "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers"]),
    ):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            parts.append(f"-- {label} --\n{result.stdout}")
        except Exception as e:
            parts.append(f"-- {label} --\n{e}")
    return "\n".join(parts)


# ── run-with-internet ──────────────────────────────────────────────────────────

def _get_user_login_env(username: str) -> dict | None:
    """Return the login-shell environment for *username* by running su as root.

    Uses ``env -0`` (NUL-delimited) so that multi-line values — in particular
    bash exported functions (BASH_FUNC_*) — are captured as single entries and
    don't confuse the parser.  BASH_FUNC_* variables are then stripped: they
    are shell-only artefacts that cause ``bash: error importing function``
    errors in every subprocess that inherits the env.

    Requires the caller to be root.  Returns None if anything goes wrong.
    """
    try:
        result = subprocess.run(
            ["su", "-", username, "-c", "bash -i -l -c 'env -0' 2>/dev/null"],
            capture_output=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        env: dict[str, str] = {}
        for entry in result.stdout.split(b"\0"):
            k, sep, v = entry.partition(b"=")
            if not sep:
                continue
            if k.startswith(b"BASH_FUNC_") or k == b"_":
                continue
            try:
                env[k.decode()] = v.decode()
            except UnicodeDecodeError:
                pass
        return env or None
    except Exception:
        return None


def run_with_internet(command: list[str], group: str) -> None:
    """Replace the current process with the command running under the internet group.

    When called as root (e.g. via ``sudo space run …``), drops back to the
    original invoking user (SUDO_USER / SUDO_UID / SUDO_GID) so that the child
    process runs with that user's full login environment — including pyenv,
    nvm, conda, etc. — while still having the internet group as its effective
    GID so that iptables ``--gid-owner`` lets traffic through.

    When called as a normal user, only the effective GID is changed (original
    behaviour: keeps real GID intact for D-Bus / SO_PEERCRED).
    """
    internet_gid = grp.getgrnam(group).gr_gid

    # ── sudo / root path ──────────────────────────────────────────────────────
    if os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER")
        sudo_uid  = int(os.environ.get("SUDO_UID", "0"))
        sudo_gid  = int(os.environ.get("SUDO_GID", "0"))

        if sudo_user and sudo_uid:
            # Get the original user's full login-shell environment (sources
            # .bash_profile / .profile / .zprofile etc., so pyenv and friends
            # are initialised properly).
            user_env = _get_user_login_env(sudo_user) or {}

            # Fallback identity vars in case su/env produced nothing.
            try:
                pw = pwd.getpwnam(sudo_user)
                user_env.setdefault("HOME", pw.pw_dir)
                user_env.setdefault("SHELL", pw.pw_shell)
            except KeyError:
                pass
            user_env.setdefault("USER", sudo_user)
            user_env.setdefault("LOGNAME", sudo_user)

            # Preserve display / session vars that the X/Wayland session set
            # in the sudo environment (they won't appear in a login shell env).
            for var in (
                "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
                "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
            ):
                val = os.environ.get(var)
                if val and var not in user_env:
                    user_env[var] = val

            # If the caller used `sudo -E` (or sudoers env_keep), overlay any
            # active virtual-environment / version-manager vars that were
            # preserved.  This covers the common case of running
            # `sudo space run pip install .` from inside an active venv.
            for var in ("VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_DEFAULT_ENV",
                        "PYENV_VERSION"):
                val = os.environ.get(var)
                if val:
                    user_env[var] = val

            # If a venv is active, prepend its bin/ so its tools take priority
            # over the pyenv shims we got from the login-shell env.
            venv = user_env.get("VIRTUAL_ENV")
            if venv:
                venv_bin = os.path.join(venv, "bin")
                path = user_env.get("PATH", "")
                if venv_bin not in path.split(":"):
                    user_env["PATH"] = venv_bin + ":" + path

            # Look up all supplementary groups the original user belongs to so
            # we can keep them (needed for group-based permissions after drop).
            try:
                extra_gids = [g.gr_gid for g in grp.getgrall() if sudo_user in g.gr_mem]
            except Exception:
                extra_gids = []

            # Order matters: set all group info before dropping UID.
            all_gids = list({internet_gid, sudo_gid, *extra_gids})
            os.setgroups(all_gids)
            os.setgid(sudo_gid)          # real GID  → original user's primary group
            os.setegid(internet_gid)     # effective GID → internet group (for iptables)
            os.setuid(sudo_uid)          # drop root (irreversible)

            os.execvpe(command[0], command, user_env)
            return  # never reached

    # ── normal (non-root) path ────────────────────────────────────────────────
    try:
        os.setegid(internet_gid)
    except PermissionError:
        # Group membership isn't active in this session yet (e.g. added after
        # login).  Re-exec under sudo -E so the environment — including any
        # active virtual environment — is preserved across the privilege jump.
        import shutil
        import sys
        argv0 = shutil.which(sys.argv[0]) or sys.argv[0]
        try:
            os.execvp("sudo", ["sudo", "-E", argv0] + sys.argv[1:])
        except Exception as exc:
            from rich.console import Console
            Console().print(f"[red]Failed to re-exec under sudo:[/red] {exc}")
            sys.exit(1)
    os.execvp(command[0], command)


# ── wrapper script ─────────────────────────────────────────────────────────────

def install_wrapper(group: str, path: str = None) -> None:
    if path is None:
        path = load_config()["wrapper_path"]
    script = f"""#!/bin/bash
# Run a command with internet access (managed by space)
# Sets only the effective GID so iptables matches while real GID stays intact
# (preserves D-Bus auth, SO_PEERCRED, and other IPC that checks real GID)
exec python3 -c "
import grp, os, sys
os.setegid(grp.getgrnam('{group}').gr_gid)
os.execvp(sys.argv[1], sys.argv[1:])
" "$@"
"""
    with open(path, "w") as f:
        f.write(script)
    os.chmod(path, 0o755)


def remove_wrapper(path: str = None) -> None:
    if path is None:
        path = load_config()["wrapper_path"]
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


# ── internet shell (network namespace) ────────────────────────────────────────

def _ns(netns_name: str, *args):
    subprocess.run(["ip", "netns", "exec", netns_name, *args], check=True)


def namespace_exists(netns_name: str) -> bool:
    result = subprocess.run(
        ["ip", "netns", "list"], capture_output=True, text=True
    )
    return netns_name in result.stdout


class _RefLock:
    """Cross-process exclusive lock using fcntl.flock."""
    def __init__(self, lock_path: str):
        self._lock_path = lock_path
        self._fd = None

    def __enter__(self):
        self._fd = open(self._lock_path, "w")
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_):
        fcntl.flock(self._fd, fcntl.LOCK_UN)
        self._fd.close()


def _get_refcount(refs_file: Path) -> int:
    try:
        return int(refs_file.read_text().strip())
    except Exception:
        return 0


def _set_refcount(refs_file: Path, n: int) -> None:
    if n <= 0:
        refs_file.unlink(missing_ok=True)
    else:
        refs_file.write_text(str(n))


def _docker_available() -> bool:
    return subprocess.run(["which", "docker"], capture_output=True).returncode == 0


def _setup_docker_network(cfg: dict) -> None:
    """Create the space-inet Docker network and add a precise FORWARD ACCEPT rule for it.

    Uses the configured bridge name so the iptables rule is deterministic.
    No-ops if Docker is not installed.
    """
    if not _docker_available():
        return
    network_name = cfg["docker_network_name"]
    bridge_name  = cfg["docker_bridge_name"]
    subnet       = cfg["docker_network_subnet"]
    gateway      = cfg["docker_network_gateway"]
    try:
        exists = subprocess.run(
            ["docker", "network", "inspect", network_name],
            capture_output=True,
        ).returncode == 0
        if not exists:
            subprocess.run([
                "docker", "network", "create",
                "--driver", "bridge",
                "--subnet", subnet,
                "--gateway", gateway,
                "--opt", f"com.docker.network.bridge.name={bridge_name}",
                network_name,
            ], check=True, capture_output=True)
    except Exception:
        pass

    # Insert ACCEPT for this bridge before the WAN DROP (position 2, after veth ACCEPT)
    wan = get_wan_interface()
    if wan:
        _assert_rule_absent("filter", "FORWARD", _TAG_FWD_DOCKER_OUT)
        subprocess.run(
            ["iptables", "-I", "FORWARD", "2",
             "-i", bridge_name, "-o", wan, "-j", "ACCEPT",
             "-m", "comment", "--comment", _TAG_FWD_DOCKER_OUT],
            check=True, capture_output=True,
        )
    # Allow return traffic (internet → container) — mirrors the -o veth-space rule for the namespace
    _assert_rule_absent("filter", "FORWARD", _TAG_FWD_DOCKER_RET)
    subprocess.run(
        ["iptables", "-A", "FORWARD",
         "-o", bridge_name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT",
         "-m", "comment", "--comment", _TAG_FWD_DOCKER_RET],
        check=True, capture_output=True,
    )


def _teardown_docker_network(cfg: dict) -> None:
    """Remove the space-inet Docker network and its FORWARD rule."""
    if not _docker_available():
        return
    network_name = cfg["docker_network_name"]
    bridge_name  = cfg["docker_bridge_name"]
    wan = get_wan_interface()
    if wan:
        _assert_rule_present("filter", "FORWARD", _TAG_FWD_DOCKER_OUT, warn_only=True,
                             context="_teardown_docker_network")
        subprocess.run(
            ["iptables", "-D", "FORWARD",
             "-i", bridge_name, "-o", wan, "-j", "ACCEPT",
             "-m", "comment", "--comment", _TAG_FWD_DOCKER_OUT],
            capture_output=True,
        )
    _assert_rule_present("filter", "FORWARD", _TAG_FWD_DOCKER_RET, warn_only=True,
                         context="_teardown_docker_network")
    subprocess.run(
        ["iptables", "-D", "FORWARD",
         "-o", bridge_name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT",
         "-m", "comment", "--comment", _TAG_FWD_DOCKER_RET],
        capture_output=True,
    )
    subprocess.run(
        ["docker", "network", "rm", network_name],
        capture_output=True,
    )


def setup_internet_namespace(dns: str = "8.8.8.8") -> None:
    """Create a network namespace with full internet access via NAT.

    If the namespace already exists (another shell is using it), the ref count
    is incremented and the existing namespace is reused — no recreation.
    """
    cfg        = load_config()
    netns_name = cfg["netns_name"]
    veth_host  = cfg["veth_host"]
    veth_ns    = cfg["veth_ns"]
    host_ip    = cfg["netns_host_ip"]
    ns_ip      = cfg["netns_ns_ip"]
    ns_subnet  = cfg["netns_subnet"]
    refs_file  = Path(f"/run/{netns_name}.refs")
    lock_path  = f"/run/{netns_name}.lock"

    with _RefLock(lock_path):
        if namespace_exists(netns_name):
            _set_refcount(refs_file, _get_refcount(refs_file) + 1)
            return

    _assert_rule_absent("nat",    "POSTROUTING", _TAG_NAT_MASQ,     context="setup_internet_namespace")
    _assert_rule_absent("filter", "FORWARD",     _TAG_FWD_VETH_IN,  context="setup_internet_namespace")
    _assert_rule_absent("filter", "FORWARD",     _TAG_FWD_VETH_OUT, context="setup_internet_namespace")

    subprocess.run(["ip", "netns", "add", netns_name], check=True)

    # veth pair: one end in host, one in namespace
    subprocess.run(
        ["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_ns],
        check=True,
    )
    subprocess.run(["ip", "link", "set", veth_ns, "netns", netns_name], check=True)

    # host side
    subprocess.run(["ip", "addr", "add", f"{host_ip}/24", "dev", veth_host], check=True)
    subprocess.run(["ip", "link", "set", veth_host, "up"], check=True)

    # namespace side
    _ns(netns_name, "ip", "addr", "add", f"{ns_ip}/24", "dev", veth_ns)
    _ns(netns_name, "ip", "link", "set", veth_ns, "up")
    _ns(netns_name, "ip", "link", "set", "lo", "up")
    _ns(netns_name, "ip", "route", "add", "default", "via", host_ip)

    # enable IP forwarding on the host so it can route namespace traffic to WAN
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")

    # NAT: masquerade traffic leaving the namespace
    subprocess.run(
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ns_subnet, "-j", "MASQUERADE",
         "-m", "comment", "--comment", _TAG_NAT_MASQ],
        check=True,
    )
    # Insert at position 1 so this ACCEPT precedes any DROP rule added by apply_rules().
    subprocess.run(
        ["iptables", "-I", "FORWARD", "1", "-i", veth_host, "-j", "ACCEPT",
         "-m", "comment", "--comment", _TAG_FWD_VETH_IN],
        check=True,
    )
    subprocess.run(
        ["iptables", "-A", "FORWARD", "-o", veth_host, "-j", "ACCEPT",
         "-m", "comment", "--comment", _TAG_FWD_VETH_OUT],
        check=True,
    )

    # DNS for the namespace
    netns_etc = Path(f"/etc/netns/{netns_name}")
    netns_etc.mkdir(parents=True, exist_ok=True)
    (netns_etc / "resolv.conf").write_text(f"nameserver {dns}\n")

    _setup_docker_network(cfg)

    with _RefLock(lock_path):
        _set_refcount(refs_file, 1)


def teardown_internet_namespace() -> bool:
    """Remove the internet namespace and clean up NAT rules.

    Decrements the ref count. The namespace is only actually torn down when
    the last shell exits (ref count reaches zero).
    """
    cfg        = load_config()
    netns_name = cfg["netns_name"]
    veth_host  = cfg["veth_host"]
    ns_subnet  = cfg["netns_subnet"]
    refs_file  = Path(f"/run/{netns_name}.refs")
    lock_path  = f"/run/{netns_name}.lock"

    with _RefLock(lock_path):
        remaining = _get_refcount(refs_file) - 1
        if remaining > 0:
            _set_refcount(refs_file, remaining)
            return False
        _set_refcount(refs_file, 0)

    # remove NAT rules (warn if absent — teardown must complete regardless)
    _assert_rule_present("nat", "POSTROUTING", _TAG_NAT_MASQ, warn_only=True,
                         context="teardown_internet_namespace")
    subprocess.run(
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", ns_subnet, "-j", "MASQUERADE",
         "-m", "comment", "--comment", _TAG_NAT_MASQ],
        capture_output=True,
    )
    _assert_rule_present("filter", "FORWARD", _TAG_FWD_VETH_IN, warn_only=True,
                         context="teardown_internet_namespace")
    subprocess.run(
        ["iptables", "-D", "FORWARD", "-i", veth_host, "-j", "ACCEPT",
         "-m", "comment", "--comment", _TAG_FWD_VETH_IN],
        capture_output=True,
    )
    _assert_rule_present("filter", "FORWARD", _TAG_FWD_VETH_OUT, warn_only=True,
                         context="teardown_internet_namespace")
    subprocess.run(
        ["iptables", "-D", "FORWARD", "-o", veth_host, "-j", "ACCEPT",
         "-m", "comment", "--comment", _TAG_FWD_VETH_OUT],
        capture_output=True,
    )

    subprocess.run(["ip", "netns", "del", netns_name], capture_output=True)

    # remove veth host end if it still exists
    subprocess.run(["ip", "link", "del", veth_host], capture_output=True)

    # remove namespace DNS config
    netns_etc = Path(f"/etc/netns/{netns_name}")
    if netns_etc.exists():
        for f in netns_etc.iterdir():
            f.unlink()
        netns_etc.rmdir()

    _teardown_docker_network(cfg)

    return True


_PRESERVED_ENV_VARS = [
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
]


# ── session registry ──────────────────────────────────────────────────────────

_SESSIONS_DIR = Path("/run/space-sessions")


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another user


def register_session(pid: int, command: list) -> int:
    """Record a background session. Returns the assigned session ID."""
    _SESSIONS_DIR.mkdir(exist_ok=True)
    existing_ids = []
    for f in _SESSIONS_DIR.glob("*.json"):
        try:
            existing_ids.append(int(f.stem))
        except ValueError:
            pass
    session_id = max(existing_ids, default=0) + 1
    (_SESSIONS_DIR / f"{session_id}.json").write_text(json.dumps({
        "id": session_id,
        "pid": pid,
        "command": command,
        "started": datetime.datetime.now().isoformat(timespec="seconds"),
    }))
    return session_id


def unregister_session(session_id: int) -> None:
    (_SESSIONS_DIR / f"{session_id}.json").unlink(missing_ok=True)


def list_sessions() -> list:
    """Return active sessions, pruning dead ones (and decrementing refcount for each)."""
    if not _SESSIONS_DIR.exists():
        return []
    sessions = []
    for f in sorted(_SESSIONS_DIR.glob("*.json"),
                    key=lambda p: int(p.stem) if p.stem.isdigit() else 0):
        try:
            data = json.loads(f.read_text())
        except Exception:
            f.unlink(missing_ok=True)
            continue
        if _is_alive(data["pid"]):
            sessions.append(data)
        else:
            f.unlink(missing_ok=True)
            teardown_internet_namespace()  # decrement refcount for the dead session
    return sessions


def kill_session(session_id: int) -> tuple:
    """Kill a session by ID. Returns (success, message)."""
    f = _SESSIONS_DIR / f"{session_id}.json"
    if not f.exists():
        return False, f"Session {session_id} not found"
    try:
        data = json.loads(f.read_text())
        pid = data["pid"]
        if _is_alive(pid):
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        f.unlink(missing_ok=True)
        teardown_internet_namespace()
        return True, f"Killed session {session_id} ({' '.join(data['command'])}, pid {pid})"
    except Exception as e:
        return False, str(e)


def run_internet_command_background(username: str, command: list) -> int:
    """Run command inside the internet namespace as username in the background.
    Returns the PID of the launched process group leader.
    """
    netns_name = load_config()["netns_name"]
    preserve = ",".join(_PRESERVED_ENV_VARS)
    proc = subprocess.Popen(
        ["ip", "netns", "exec", netns_name,
         "sudo", "-u", username, f"--preserve-env={preserve}", "--", *command],
        start_new_session=True,
    )
    return proc.pid


def run_internet_shell(username: str, shell: str = "/bin/bash") -> subprocess.Popen:
    """
    Enter the internet namespace and launch an interactive shell as username.
    Must be called as root (ip netns exec requires it).
    The shell itself runs as the real user — sudo inside still works because
    child processes inherit the namespace regardless of UID/GID changes.
    Display-related env vars are preserved so GUI apps (Chrome, etc.) work.
    Returns the Popen object (caller should call .wait()).
    """
    netns_name = load_config()["netns_name"]
    preserve = ",".join(_PRESERVED_ENV_VARS)
    return subprocess.Popen(
        ["ip", "netns", "exec", netns_name,
         "sudo", "-u", username, f"--preserve-env={preserve}", "--", shell],
    )
