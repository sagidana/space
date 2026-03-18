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

- **iptables** blocks all outbound traffic except to your LAN subnets
- A Linux group (`internet`) is created; processes in that group are allowed through
- `space run <cmd>` and the `inet` wrapper run commands under that group via `sg`

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
2. Create the `internet` Linux group and add you to it
3. Apply iptables rules
4. Install the `/usr/local/bin/inet` shortcut wrapper
5. Add `alias space='sudo /path/to/space'` to your `~/.bashrc` or `~/.zshrc` so you can type `space` directly without prefixing `sudo` every time

Then open a new shell (or run `newgrp internet`) for group membership and the alias to take effect.

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
sudo space shell --dns 1.1.1.1      # use a different DNS server
sudo space shell --shell /bin/zsh   # use a different shell
```

> **Why this works for sudo:** The network namespace is inherited by all child processes regardless of UID/GID changes. Unlike the `sg`-based approach, sudo inside the shell stays in the same namespace.

### Enable / disable blocking

```bash
sudo space on     # enable blocking (default after init)
sudo space off    # disable blocking (allow all traffic)
sudo space panic  # emergency: clear all rules immediately, no confirmation prompt
```

### Show status

```bash
space status
```

```
  Initialized        yes
  Blocking internet  yes
  LAN subnets        192.168.1.0/24
  Internet group     internet
  inet wrapper       /usr/local/bin/inet

iptables OUTPUT chain:
num  target  prot  ...
1    ACCEPT  all   -- lo
2    ACCEPT  all   -- 192.168.1.0/24
3    ACCEPT  all   -- state RELATED,ESTABLISHED
4    ACCEPT  all   -- owner GID match internet
5    DROP    all
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
| `space off` | yes | Disable internet blocking |
| `space status` | no | Show status and iptables rules |
| `space run <cmd>` | no | Run a command with internet access |
| `space shell` | yes | Launch a shell with full internet access (sudo-safe) |
| `space subnet` | yes | Re-detect or update LAN subnets |
| `space save` | yes | Persist rules via `netfilter-persistent` |
| `space panic` | yes | Emergency: clear all rules, restore full internet access immediately |
| `space uninstall` | yes | Remove rules and `inet` wrapper |

## Notes

- **DNS**: If your router (e.g. `192.168.1.1`) serves DNS, it is already covered by the LAN rule. If you use a public DNS like `8.8.8.8`, either add it as a subnet or point `/etc/resolv.conf` to your router.
- **sudo + internet**: `sudo` drops group membership by default. Use `sudo sg internet -c "apt update"` or configure `sudo` to preserve groups.
- **IPv6**: Only IPv4 is managed. If you use IPv6, apply equivalent rules with `ip6tables` manually.
- **Config location**: `~/.config/space/config.json` (always stored as the real user, even when run via sudo).
