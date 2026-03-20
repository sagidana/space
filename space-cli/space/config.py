import json
import os
import pwd
from pathlib import Path

DEFAULTS = {
    # firewall / user config (set during init)
    "subnets": [],
    "dns": None,
    "group": "internet",
    "initialized": False,
    "wrapper_installed": False,
    "username": None,
    # inet wrapper
    "wrapper_path": "/usr/local/bin/inet",
    # network namespace
    "netns_name": "space-inet",
    "veth_host": "veth-space",
    "veth_ns": "veth-inet",
    "netns_host_ip": "10.200.200.1",
    "netns_ns_ip": "10.200.200.2",
    "netns_subnet": "10.200.200.0/24",
    # docker integration
    "docker_network_name": "space-inet-net",
    "docker_bridge_name": "br-space-inet",
    "docker_network_subnet": "10.200.201.0/24",
    "docker_network_gateway": "10.200.201.1",
}


def _real_home() -> Path:
    """Return the home directory of the invoking user, even under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


def _config_dir() -> Path:
    return _real_home() / ".config" / "space"


def load():
    config_file = _config_dir() / "config.json"
    if not config_file.exists():
        return DEFAULTS.copy()
    with open(config_file) as f:
        return {**DEFAULTS, **json.load(f)}


def save(config):
    config_dir = _config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "config.json"
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)
