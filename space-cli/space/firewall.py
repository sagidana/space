import grp
import os
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

def run_with_internet(command: list[str], group: str) -> None:
    """Replace the current process with the command running under the internet group.

    Sets only the effective GID (not the real GID) so that iptables --gid-owner
    matches while D-Bus, SO_PEERCRED, and other IPC mechanisms still see the
    user's real primary group.
    """
    internet_gid = grp.getgrnam(group).gr_gid
    try:
        os.setegid(internet_gid)
    except PermissionError:
        import sys
        from rich.console import Console
        Console().print(
            f"\n[red]Permission denied:[/red] cannot switch to group '[bold]{group}[/bold]'.\n\n"
            f"Run the command with sudo:\n\n"
            f"  [bold]sudo space run {' '.join(command)}[/bold]"
        )
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


def _ns(*args):
    subprocess.run(["ip", "netns", "exec", NETNS_NAME, *args], check=True)


def namespace_exists() -> bool:
    result = subprocess.run(
        ["ip", "netns", "list"], capture_output=True, text=True
    )
    return NETNS_NAME in result.stdout


def setup_internet_namespace(dns: str = "8.8.8.8") -> None:
    """Create a network namespace with full internet access via NAT."""
    if namespace_exists():
        teardown_internet_namespace()

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


def teardown_internet_namespace() -> None:
    """Remove the internet namespace and clean up NAT rules."""
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
