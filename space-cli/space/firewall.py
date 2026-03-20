import fcntl
import grp
import os
import pwd
import subprocess
from pathlib import Path


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

def _ipt(*args):
    subprocess.run(["iptables", *args], check=True)


def _ip6t(*args):
    subprocess.run(["ip6tables", *args], check=True)


def apply_rules(subnets: list[str], group: str) -> None:
    """Block all outbound internet traffic; allow loopback, LAN, and the internet group."""
    # ── IPv4 ──────────────────────────────────────────────────────────────────
    _ipt("-F", "OUTPUT")
    _ipt("-P", "OUTPUT", "ACCEPT")          # reset policy first

    _ipt("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")

    for subnet in subnets:
        _ipt("-A", "OUTPUT", "-d", subnet, "-j", "ACCEPT")

    _ipt("-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
    _ipt("-A", "OUTPUT", "-m", "owner", "--gid-owner", group, "-j", "ACCEPT")
    _ipt("-A", "OUTPUT", "-j", "DROP")

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    _ip6t("-F", "OUTPUT")
    _ip6t("-P", "OUTPUT", "ACCEPT")         # reset policy first

    _ip6t("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
    # Allow link-local (needed for neighbour discovery / ICMPv6)
    _ip6t("-A", "OUTPUT", "-d", "fe80::/10", "-j", "ACCEPT")

    _ip6t("-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
    _ip6t("-A", "OUTPUT", "-m", "owner", "--gid-owner", group, "-j", "ACCEPT")
    _ip6t("-A", "OUTPUT", "-j", "DROP")


def remove_rules() -> None:
    """Flush OUTPUT chain and restore ACCEPT policy."""
    _ipt("-F", "OUTPUT")
    _ipt("-P", "OUTPUT", "ACCEPT")
    _ip6t("-F", "OUTPUT")
    _ip6t("-P", "OUTPUT", "ACCEPT")


def save_rules() -> None:
    """Persist rules via netfilter-persistent (iptables-persistent package)."""
    subprocess.run(["netfilter-persistent", "save"], check=True)


def is_blocking() -> bool:
    """Return True if a DROP rule exists in the OUTPUT chain (IPv4 or IPv6)."""
    for cmd in (["iptables", "-L", "OUTPUT", "-n"], ["ip6tables", "-L", "OUTPUT", "-n"]):
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
        ("iptables", ["iptables", "-L", "OUTPUT", "-n", "--line-numbers"]),
        ("ip6tables", ["ip6tables", "-L", "OUTPUT", "-n", "--line-numbers"]),
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

WRAPPER_PATH = "/usr/local/bin/inet"


def install_wrapper(group: str) -> None:
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
    with open(WRAPPER_PATH, "w") as f:
        f.write(script)
    os.chmod(WRAPPER_PATH, 0o755)


def remove_wrapper() -> None:
    try:
        os.remove(WRAPPER_PATH)
    except FileNotFoundError:
        pass


# ── internet shell (network namespace) ────────────────────────────────────────

NETNS_NAME = "space-inet"
VETH_HOST  = "veth-space"
VETH_NS    = "veth-inet"
_HOST_IP   = "10.200.200.1"
_NS_IP     = "10.200.200.2"
_NS_SUBNET = "10.200.200.0/24"

_REFCOUNT_FILE = Path("/run/space-inet.refs")
_REFCOUNT_LOCK = "/run/space-inet.lock"


def _ns(*args):
    subprocess.run(["ip", "netns", "exec", NETNS_NAME, *args], check=True)


def namespace_exists() -> bool:
    result = subprocess.run(
        ["ip", "netns", "list"], capture_output=True, text=True
    )
    return NETNS_NAME in result.stdout


class _RefLock:
    """Cross-process exclusive lock using fcntl.flock."""
    def __init__(self):
        self._fd = None

    def __enter__(self):
        self._fd = open(_REFCOUNT_LOCK, "w")
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_):
        fcntl.flock(self._fd, fcntl.LOCK_UN)
        self._fd.close()


def _get_refcount() -> int:
    try:
        return int(_REFCOUNT_FILE.read_text().strip())
    except Exception:
        return 0


def _set_refcount(n: int) -> None:
    if n <= 0:
        _REFCOUNT_FILE.unlink(missing_ok=True)
    else:
        _REFCOUNT_FILE.write_text(str(n))


def setup_internet_namespace(dns: str = "8.8.8.8") -> None:
    """Create a network namespace with full internet access via NAT.

    If the namespace already exists (another shell is using it), the ref count
    is incremented and the existing namespace is reused — no recreation.
    """
    with _RefLock():
        if namespace_exists():
            _set_refcount(_get_refcount() + 1)
            return

    subprocess.run(["ip", "netns", "add", NETNS_NAME], check=True)

    # veth pair: one end in host, one in namespace
    subprocess.run(
        ["ip", "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS],
        check=True,
    )
    subprocess.run(["ip", "link", "set", VETH_NS, "netns", NETNS_NAME], check=True)

    # host side
    subprocess.run(["ip", "addr", "add", f"{_HOST_IP}/24", "dev", VETH_HOST], check=True)
    subprocess.run(["ip", "link", "set", VETH_HOST, "up"], check=True)

    # namespace side
    _ns("ip", "addr", "add", f"{_NS_IP}/24", "dev", VETH_NS)
    _ns("ip", "link", "set", VETH_NS, "up")
    _ns("ip", "link", "set", "lo", "up")
    _ns("ip", "route", "add", "default", "via", _HOST_IP)

    # enable IP forwarding
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")

    # NAT: masquerade traffic leaving the namespace
    subprocess.run(
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", _NS_SUBNET, "-j", "MASQUERADE"],
        check=True,
    )
    subprocess.run(["iptables", "-A", "FORWARD", "-i", VETH_HOST, "-j", "ACCEPT"], check=True)
    subprocess.run(["iptables", "-A", "FORWARD", "-o", VETH_HOST, "-j", "ACCEPT"], check=True)

    # DNS for the namespace
    netns_etc = Path(f"/etc/netns/{NETNS_NAME}")
    netns_etc.mkdir(parents=True, exist_ok=True)
    (netns_etc / "resolv.conf").write_text(f"nameserver {dns}\n")

    with _RefLock():
        _set_refcount(1)


def teardown_internet_namespace() -> None:
    """Remove the internet namespace and clean up NAT rules.

    Decrements the ref count. The namespace is only actually torn down when
    the last shell exits (ref count reaches zero).
    """
    with _RefLock():
        remaining = _get_refcount() - 1
        if remaining > 0:
            _set_refcount(remaining)
            return False
        _set_refcount(0)

    # remove NAT rules (ignore errors — may not exist)
    subprocess.run(
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", _NS_SUBNET, "-j", "MASQUERADE"],
        capture_output=True,
    )
    subprocess.run(
        ["iptables", "-D", "FORWARD", "-i", VETH_HOST, "-j", "ACCEPT"],
        capture_output=True,
    )
    subprocess.run(
        ["iptables", "-D", "FORWARD", "-o", VETH_HOST, "-j", "ACCEPT"],
        capture_output=True,
    )

    subprocess.run(["ip", "netns", "del", NETNS_NAME], capture_output=True)

    # remove veth host end if it still exists
    subprocess.run(["ip", "link", "del", VETH_HOST], capture_output=True)

    # remove namespace DNS config
    netns_etc = Path(f"/etc/netns/{NETNS_NAME}")
    if netns_etc.exists():
        for f in netns_etc.iterdir():
            f.unlink()
        netns_etc.rmdir()

    return True


_PRESERVED_ENV_VARS = [
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
]


def run_internet_shell(username: str, shell: str = "/bin/bash") -> int:
    """
    Enter the internet namespace and launch an interactive shell as username.
    Must be called as root (ip netns exec requires it).
    The shell itself runs as the real user — sudo inside still works because
    child processes inherit the namespace regardless of UID/GID changes.
    Display-related env vars are preserved so GUI apps (Chrome, etc.) work.
    Returns the shell's exit code.
    """
    preserve = ",".join(_PRESERVED_ENV_VARS)
    result = subprocess.run(
        ["ip", "netns", "exec", NETNS_NAME,
         "sudo", "-u", username, f"--preserve-env={preserve}", "--", shell],
    )
    return result.returncode
