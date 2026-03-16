import re
import subprocess


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
