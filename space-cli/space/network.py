import re
import subprocess
from pathlib import Path


def get_system_dns() -> str | None:
    """Detect the system's upstream DNS server.

    Reads /etc/resolv.conf.  If that resolves to a loopback address
    (e.g. 127.0.0.53 used by systemd-resolved), falls back to
    /run/systemd/resolve/resolv.conf which lists the real upstream servers.
    Returns None if nothing useful is found.
    """
    def _first_nameserver(path: str) -> str | None:
        try:
            for line in Path(path).read_text().splitlines():
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
        except Exception:
            pass
        return None

    dns = _first_nameserver("/etc/resolv.conf")
    if dns and (dns.startswith("127.") or dns == "::1"):
        # loopback stub resolver — try to get the real upstream
        upstream = _first_nameserver("/run/systemd/resolve/resolv.conf")
        if upstream:
            dns = upstream
    return dns


def get_local_subnets() -> list[str]:
    """Detect private LAN subnets from the routing table."""
    try:
        result = subprocess.run(
            ["ip", "route", "show"],
            capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    subnets = []
    for line in result.stdout.splitlines():
        if line.startswith("default"):
            continue
        match = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not match:
            continue
        subnet = match.group(1)
        if (
            subnet.startswith("192.168.")
            or subnet.startswith("10.")
            or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", subnet)
        ):
            subnets.append(subnet)

    return list(dict.fromkeys(subnets))  # deduplicate, preserve order
