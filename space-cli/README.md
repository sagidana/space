# space

Make internet access **explicit, not implicit** on your Linux machine.

By default, all outbound internet traffic is blocked. LAN access works normally.
To reach the internet, you must consciously opt in — per command.

```bash
curl https://example.com          # blocked
ping 192.168.1.1                  # works (LAN)
space run curl https://example.com  # works
inet firefox                        # works
```

## How it works

- **iptables** and **ip6tables** block all outbound traffic (IPv4 and IPv6) except to your LAN subnets
- The FORWARD chain is also blocked so containers/VMs cannot reach the internet through the host
- A Linux group (`internet`) is created; processes in that group are allowed through
- `space run <cmd>` and the `inet` wrapper run commands under that group
- `space shell` creates a network namespace with NAT, giving full internet access to everything inside it

## Install

Install **system-wide** so `sudo space` can find the command:

```bash
sudo pip install .
```

This places `space` in `/usr/local/bin/`, which is on sudo's PATH.

> **Do not install as a regular user** (`pip install .` without sudo). It would land in `~/.local/bin/` which sudo cannot find, so `sudo space init` would fail with "command not found".

Requires Python 3.8+ and a Linux system with `iptables`.

## Setup

Run once to configure everything:

```bash
sudo space init
```

This will:
1. Auto-detect your LAN subnets (e.g. `192.168.1.0/24`) and ask you to confirm
2. Auto-detect your system DNS server and ask you to confirm
3. Create the `internet` Linux group and add you to it
4. Apply iptables/ip6tables rules
5. Install the `/usr/local/bin/inet` shortcut wrapper
6. Create a symlink `/usr/bin/space` → the installed binary so `sudo space` works from any context

The detected DNS is saved to config and used automatically by `space shell`. On systems using `systemd-resolved` (where `/etc/resolv.conf` points to `127.0.0.53`), the real upstream DNS is read from `/run/systemd/resolve/resolv.conf` instead.

Then open a new shell (or run `newgrp internet`) for group membership to take effect.

### Persist rules across reboots

```bash
sudo apt install iptables-persistent
sudo space save
```

## Usage

### Run a command with internet access

```bash
space run curl https://example.com
space run firefox
space run -- python script.py --some-flag   # use -- for commands with flags
inet curl https://example.com               # shorthand wrapper
```

### Launch a shell with full internet access

```bash
sudo space shell
```

Opens an interactive shell where **everything has internet access** — including `sudo apt update`, background processes, and any subcommand. Uses a temporary network namespace under the hood; the namespace is torn down automatically when you exit the shell.

```bash
sudo space shell --dns 1.1.1.1      # override DNS for this session
sudo space shell --shell /bin/zsh   # use a different shell
```

The DNS defaults to whatever was saved during `space init`. You only need `--dns` if you want to override it for a specific session.

> **Why this works for sudo:** The network namespace is inherited by all child processes regardless of UID/GID changes. Unlike the `sg`-based approach, sudo inside the shell stays in the same namespace.

### Run a background command in the internet namespace

```bash
sudo space shell firefox       # launch firefox with internet access in background
sudo space shell git push      # run git push with internet access
```

When arguments are given to `space shell`, the command is launched as a background session inside the namespace. The namespace stays alive until you kill the session or all sessions exit.

### Manage sessions

```bash
sudo space shells              # list all active internet namespace sessions
sudo space kill <id>           # kill a specific session by ID
sudo space killall             # kill all active sessions
```

### Docker integration

When `space shell` sets up the internet namespace, it also creates a Docker network (`space-inet-net`) if Docker is installed. Containers attached to this network get internet access through the namespace:

```bash
sudo space shell
docker run --network space-inet-net --dns <your-dns> myimage
```

Use `--dns` when running containers if DNS resolution fails (Docker's embedded DNS proxy is blocked by the firewall).

### Enable / disable blocking

```bash
sudo space on     # enable blocking (default after init)
sudo space off    # disable blocking (allow all traffic)
sudo space panic  # emergency: clear all rules immediately, no confirmation prompt
```

### Show status

```bash
sudo space status
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
sudo space subnet
```

### Uninstall

```bash
sudo space uninstall          # removes rules and /usr/local/bin/inet
sudo groupdel internet        # optional: remove the group
```

## Commands

| Command | sudo | Description |
|---|---|---|
| `space init` | yes | First-time setup wizard |
| `space on` | yes | Enable internet blocking |
| `space off` | yes | Disable internet blocking (prompts for confirmation) |
| `space status` | yes | Show status and firewall rules |
| `space run <cmd>` | no | Run a command with internet access |
| `space shell` | yes | Launch an interactive shell with full internet access |
| `space shell <cmd>` | yes | Run a command in the background inside the internet namespace |
| `space shells` | yes | List all active internet namespace sessions |
| `space kill <id>` | yes | Kill a specific session by ID |
| `space killall` | yes | Kill all active sessions |
| `space subnet` | yes | Re-detect or update LAN subnets |
| `space save` | yes | Persist rules via `netfilter-persistent` |
| `space panic` | yes | Emergency: clear all rules, restore full internet access immediately |
| `space uninstall` | yes | Remove rules and `inet` wrapper |

## Notes

- **DNS**: `space init` auto-detects your system DNS and saves it to config. It handles `systemd-resolved` transparently — if `/etc/resolv.conf` points to `127.0.0.53`, the real upstream server is read from `/run/systemd/resolve/resolv.conf`. The saved DNS is used by `space shell`; override it per-session with `--dns`.
- **sudo + internet**: `sudo` drops group membership by default. Use `sudo sg internet -c "apt update"` or configure `sudo` to preserve groups.
- **IPv6**: Both IPv4 (`iptables`) and IPv6 (`ip6tables`) are managed. Link-local addresses (`fe80::/10`) are always allowed for neighbour discovery / ICMPv6.
- **Config location**: `~/.config/space/config.json` (always stored as the real user, even when run via sudo).
