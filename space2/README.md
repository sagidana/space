sudo chmod +x /etc/network-policy.sh

sudo systemctl enable lan-only.service
sudo systemctl start lan-only.service

sudo chmod +x /usr/local/bin/online

# Open an internet-enabled shell session
sudo online

# Run a single program with internet
sudo online firefox

# Run curl with internet
sudo online curl https://example.com

# Run apt with internet
sudo online apt update
```

Everything **outside** of `sudo online` has zero internet access but full LAN access.

---

## Summary

| Context | LAN | Internet |
|---|---|---|
| Normal desktop | ✅ | ❌ |
| `sudo online <app>` | ✅ | ✅ |

---

## Tips

- You can alias it: `alias inet='sudo online'` in your `~/.bashrc`
- To make specific users able to run `online` without a password, add to `/etc/sudoers`:
```
  youruser ALL=(ALL) NOPASSWD: /usr/local/bin/online

