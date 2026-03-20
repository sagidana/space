# space

Make internet access **explicit, not implicit** on your Linux machine.

By default, all outbound internet traffic is blocked. LAN access works normally.
To reach the internet, you must consciously opt in — per command.

```bash
curl https://example.com          # blocked
ping 192.168.1.1                  # works (LAN)
space curl https://example.com    # works
inet firefox                      # works
```

## How it works

- **iptables** and **ip6tables** block all outbound traffic (IPv4 and IPv6) except to your LAN subnets
- The FORWARD chain is also blocked so containers/VMs cannot reach the internet through the host
- A Linux group (`internet`) is created; processes in that group are allowed through
- `space <cmd>` and the `inet` wrapper run commands under that group
- `space shell` creates a network namespace with NAT, giving full internet access to everything inside it

## Install

Install from inside your pyenv environment:

```bash
pip install .
```

Requires Python 3.8+ and a Linux system with `iptables`.

## Setup

Run once to configure everything:

```bash
space init
```

This will re-execute itself with `sudo` to perform system-level setup:
1. Auto-detect your LAN subnets (e.g. `192.168.1.0/24`) and ask you to confirm
2. Auto-detect your system DNS server and ask you to confirm
3. Create the `internet` Linux group and add you to it
4. Apply iptables/ip6tables rules
5. Install the `/usr/local/bin/inet` shortcut wrapper
6. Create a symlink `/usr/bin/space` → the installed binary so `space` works from any context

The detected DNS is saved to config and used automatically by `space shell`. On systems using `systemd-resolved` (where `/etc/resolv.conf` points to `127.0.0.53`), the real upstream DNS is read from `/run/systemd/resolve/resolv.conf` instead.

Then open a new shell (or run `newgrp internet`) for group membership to take effect.

### Persist rules across reboots

```bash
sudo apt install iptables-persistent
space save
```

## Usage

### Run a command with internet access

```bash
space curl https://example.com
space firefox
space -- python script.py --some-flag   # use -- for commands with flags
inet curl https://example.com           # shorthand wrapper
```

### Launch a shell with full internet access

```bash
space shell
```

Opens an interactive shell where **everything has internet access** — including `sudo apt update`, background processes, and any subcommand. Uses a temporary network namespace under the hood; the namespace is torn down automatically when you exit the shell.

```bash
space shell --dns 1.1.1.1      # override DNS for this session
space shell --shell /bin/zsh   # use a different shell
```

The DNS defaults to whatever was saved during `space init`. You only need `--dns` if you want to override it for a specific session.

> **Why this works for sudo:** The network namespace is inherited by all child processes regardless of UID/GID changes. Unlike the `sg`-based approach, sudo inside the shell stays in the same namespace.

### Run a background command in the internet namespace

```bash
space shell firefox       # launch firefox with internet access in background
space shell git push      # run git push with internet access
```

When arguments are given to `space shell`, the command is launched as a background session inside the namespace. The namespace stays alive until you kill the session or all sessions exit.

### Manage sessions

```bash
space shells              # list all active internet namespace sessions
space kill <id>           # kill a specific session by ID
space killall             # kill all active sessions
```

### Docker integration

When `space shell` sets up the internet namespace, it also creates a Docker network (`space-inet-net`) if Docker is installed. Containers attached to this network get internet access through the namespace:

```bash
space shell
docker run --network space-inet-net --dns <your-dns> myimage
```

Use `--dns` when running containers if DNS resolution fails (Docker's embedded DNS proxy is blocked by the firewall).

### Enable / disable blocking

```bash
space on     # enable blocking (default after init)
space off    # disable blocking (allow all traffic)
space panic  # emergency: clear all rules immediately, no confirmation prompt
```

### Show status

```bash
space status
```

```
  Initialized        yes
  Blocking internet  yes
  LAN subnets        192.168.1.0/24
  Namespace DNS      192.168.1.1
  Internet group     internet
  inet wrapper       /usr/local/bin/inet

-- iptables OUTPUT --
num  target  prot  ...
1    ACCEPT  all   -- lo
2    ACCEPT  all   -- 192.168.1.0/24
3    ACCEPT  all   -- state RELATED,ESTABLISHED
4    ACCEPT  all   -- owner GID match internet
5    DROP    all

-- ip6tables OUTPUT --
num  target  prot  ...
1    ACCEPT  all   -- lo
2    ACCEPT  all   -- fe80::/10
3    ACCEPT  all   -- state RELATED,ESTABLISHED
4    ACCEPT  all   -- owner GID match internet
5    DROP    all

-- iptables FORWARD --
num  target  prot  ...
1    DROP    all   -- out: eth0

-- iptables nat POSTROUTING --
...
```

### Update LAN subnets

If you change networks (e.g. new router, VPN), update your allowed subnets:

```bash
space subnet
```

### Uninstall

```bash
space uninstall               # removes rules and /usr/local/bin/inet
sudo groupdel internet        # optional: remove the group
```

## Commands

| Command | Description |
|---|---|
| `space init` | First-time setup wizard (auto-escalates to sudo) |
| `space on` | Enable internet blocking (auto-escalates to sudo) |
| `space off` | Disable internet blocking — prompts for confirmation (auto-escalates to sudo) |
| `space status` | Show status and firewall rules (auto-escalates to sudo) |
| `space <cmd>` | Run a command with internet access |
| `space shell` | Launch an interactive shell with full internet access (auto-escalates to sudo) |
| `space shell <cmd>` | Run a command in the background inside the internet namespace (auto-escalates to sudo) |
| `space shells` | List all active internet namespace sessions (auto-escalates to sudo) |
| `space kill <id>` | Kill a specific session by ID (auto-escalates to sudo) |
| `space killall` | Kill all active sessions (auto-escalates to sudo) |
| `space subnet` | Re-detect or update LAN subnets (auto-escalates to sudo) |
| `space save` | Persist rules via `netfilter-persistent` (auto-escalates to sudo) |
| `space panic` | Emergency: clear all rules, restore full internet access immediately (auto-escalates to sudo) |
| `space uninstall` | Remove rules and `inet` wrapper (auto-escalates to sudo) |

## Notes

- **DNS**: `space init` auto-detects your system DNS and saves it to config. It handles `systemd-resolved` transparently — if `/etc/resolv.conf` points to `127.0.0.53`, the real upstream server is read from `/run/systemd/resolve/resolv.conf`. The saved DNS is used by `space shell`; override it per-session with `--dns`.
- **sudo + internet**: `sudo` drops group membership by default. Use `sudo sg internet -c "apt update"` or configure `sudo` to preserve groups.
- **IPv6**: Both IPv4 (`iptables`) and IPv6 (`ip6tables`) are managed. Link-local addresses (`fe80::/10`) are always allowed for neighbour discovery / ICMPv6.
- **Config location**: `~/.config/space/config.json` (always stored as the real user, even when run via sudo).
