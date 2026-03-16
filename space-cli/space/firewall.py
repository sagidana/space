import grp
import os
import shlex
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


def apply_rules(subnets: list[str], group: str) -> None:
    """Block all outbound internet traffic; allow loopback, LAN, and the internet group."""
    _ipt("-F", "OUTPUT")
    _ipt("-P", "OUTPUT", "ACCEPT")          # reset policy first

    _ipt("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")

    for subnet in subnets:
        _ipt("-A", "OUTPUT", "-d", subnet, "-j", "ACCEPT")

    _ipt("-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
    _ipt("-A", "OUTPUT", "-m", "owner", "--gid-owner", group, "-j", "ACCEPT")
    _ipt("-A", "OUTPUT", "-j", "DROP")


def remove_rules() -> None:
    """Flush OUTPUT chain and restore ACCEPT policy."""
    _ipt("-F", "OUTPUT")
    _ipt("-P", "OUTPUT", "ACCEPT")


def save_rules() -> None:
    """Persist rules via netfilter-persistent (iptables-persistent package)."""
    subprocess.run(["netfilter-persistent", "save"], check=True)


def is_blocking() -> bool:
    """Return True if a DROP rule exists in the OUTPUT chain."""
    try:
        result = subprocess.run(
            ["iptables", "-L", "OUTPUT", "-n"],
            capture_output=True, text=True, check=True,
        )
        return "DROP" in result.stdout
    except Exception:
        return False


def get_rules_text() -> str:
    try:
        result = subprocess.run(
            ["iptables", "-L", "OUTPUT", "-n", "--line-numbers"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout
    except Exception as e:
        return str(e)


# ── run-with-internet ──────────────────────────────────────────────────────────

def run_with_internet(command: list[str], group: str) -> None:
    """Replace the current process with the command running under the internet group."""
    cmd_str = " ".join(shlex.quote(arg) for arg in command)
    os.execvp("sg", ["sg", group, "-c", cmd_str])


# ── wrapper script ─────────────────────────────────────────────────────────────

WRAPPER_PATH = "/usr/local/bin/inet"


def install_wrapper(group: str) -> None:
    script = f"""#!/bin/bash
# Run a command with internet access (managed by space)
exec sg {group} -c "$*"
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
