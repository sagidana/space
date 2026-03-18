import os
import pwd
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import firewall
from .config import load as load_config, save as save_config
from .network import get_local_subnets

console = Console()


# ── helpers ────────────────────────────────────────────────────────────────────

def require_root():
    if os.geteuid() != 0:
        console.print("[red]This command requires root. Run with sudo.[/red]")
        # Detect the common case: installed as a regular user instead of system-wide
        import shutil
        space_path = shutil.which("space") or ""
        if "/.local/" in space_path:
            console.print(
                "[yellow]Hint:[/yellow] space is installed in your user directory "
                f"({space_path}), so [bold]sudo space[/bold] won't find it.\n"
                "Reinstall system-wide:\n\n"
                "  [bold]sudo pip install <path-to-space-cli>[/bold]\n"
            )
        sys.exit(1)


def need_init(config):
    if not config.get("initialized"):
        console.print(
            "[yellow]space is not initialized. Run [bold]sudo space init[/bold] first.[/yellow]"
        )
        sys.exit(1)


_ALIAS_MARKER = "# added by space"


def _shell_rc_file(username: str) -> Path | None:
    """Return the rc file for the user's login shell, or None if unsupported."""
    try:
        entry = pwd.getpwnam(username)
        home = Path(entry.pw_dir)
        shell = Path(entry.pw_shell).name
    except KeyError:
        return None
    if shell in ("bash",):
        return home / ".bashrc"
    if shell in ("zsh",):
        return home / ".zshrc"
    return None


def install_shell_alias(username: str, space_bin: Path) -> tuple[bool, str]:
    """Append `alias space='sudo <space_bin>'` to the user's shell rc file."""
    rc = _shell_rc_file(username)
    if rc is None:
        shell = Path(pwd.getpwnam(username).pw_shell).name
        return False, (
            f"Unsupported shell '{shell}' — add manually: "
            f"alias space='sudo {space_bin}'"
        )

    alias_line = f"alias space='sudo {space_bin}'"
    if rc.exists() and (_ALIAS_MARKER in rc.read_text() or alias_line in rc.read_text()):
        return True, f"Alias already present in {rc}"

    with rc.open("a") as f:
        f.write(f"\n{_ALIAS_MARKER}\n{alias_line}\n")
    return True, f"Added alias to {rc}"


def remove_shell_alias(username: str) -> bool:
    """Remove the alias block previously written by install_shell_alias."""
    try:
        rc = _shell_rc_file(username)
    except Exception:
        return False
    if rc is None or not rc.exists():
        return False

    lines = rc.read_text().splitlines(keepends=True)
    filtered = []
    skip_next = False
    for line in lines:
        if line.strip() == _ALIAS_MARKER:
            skip_next = True
            # also drop the preceding blank line we added
            if filtered and filtered[-1].strip() == "":
                filtered.pop()
            continue
        if skip_next and line.startswith("alias space="):
            skip_next = False
            continue
        filtered.append(line)

    rc.write_text("".join(filtered))
    return True


# ── CLI ────────────────────────────────────────────────────────────────────────

@click.group()
def main():
    """space — make internet access explicit, not implicit."""


# ── init ───────────────────────────────────────────────────────────────────────

@main.command()
def init():
    """First-time setup: detect subnet, create group, apply firewall rules."""
    require_root()
    config = load_config()

    console.print("\n[bold cyan]space — internet isolation setup[/bold cyan]\n")

    # ── subnet detection ──────────────────────────────────────────────────────
    detected = get_local_subnets()
    if detected:
        console.print(f"[green]Detected LAN subnets:[/green] {', '.join(detected)}")
        use_detected = Confirm.ask("Use these subnets for LAN access?", default=True)
    else:
        console.print("[yellow]Could not auto-detect private subnets.[/yellow]")
        use_detected = False

    if use_detected:
        subnets = detected
    else:
        raw = Prompt.ask(
            "Enter subnets (comma-separated, e.g. 192.168.1.0/24,10.0.0.0/8)"
        )
        subnets = [s.strip() for s in raw.split(",") if s.strip()]

    if not subnets:
        console.print("[red]No subnets provided. Aborting.[/red]")
        sys.exit(1)

    # ── group name ────────────────────────────────────────────────────────────
    group = Prompt.ask("Internet-access group name", default="internet")

    # real user (when invoked via sudo)
    username = os.environ.get("SUDO_USER") or os.environ.get("USER")

    # ── confirm ───────────────────────────────────────────────────────────────
    console.print()
    console.print("[bold]Summary[/bold]")
    console.print(f"  LAN subnets  : {', '.join(subnets)}")
    console.print(f"  Group        : {group}")
    console.print(f"  Add user     : {username or '(unknown)'}")
    console.print(f"  Wrapper      : /usr/local/bin/inet")
    console.print()

    if not Confirm.ask("Apply?", default=True):
        console.print("Aborted.")
        return

    # ── apply ─────────────────────────────────────────────────────────────────
    if not firewall.group_exists(group):
        firewall.create_group(group)
        console.print(f"[green]✓[/green] Created group [bold]{group}[/bold]")
    else:
        console.print(f"[dim]  Group '{group}' already exists[/dim]")

    if username:
        firewall.add_user_to_group(username, group)
        console.print(f"[green]✓[/green] Added [bold]{username}[/bold] to group [bold]{group}[/bold]")

    firewall.apply_rules(subnets, group)
    console.print("[green]✓[/green] Applied iptables rules")

    firewall.install_wrapper(group)
    console.print("[green]✓[/green] Installed [bold]/usr/local/bin/inet[/bold]")

    config.update({
        "subnets": subnets,
        "group": group,
        "initialized": True,
        "wrapper_installed": True,
        "username": username,
    })
    save_config(config)
    console.print("[green]✓[/green] Saved config to ~/.config/space/config.json")

    # Install shell alias so the user can type `space` instead of `sudo space`
    space_bin = Path(sys.executable).parent / "space"
    if username and space_bin.exists():
        ok, msg = install_shell_alias(username, space_bin)
        if ok:
            console.print(f"[green]✓[/green] {msg}")
        else:
            console.print(f"[yellow]![/yellow] Shell alias skipped: {msg}")

    console.print()
    console.print("[bold green]Done![/bold green]")
    console.print()
    console.print("  Internet is now [bold red]blocked[/bold red] by default.")
    console.print(f"  Use [bold]space run <cmd>[/bold] or [bold]inet <cmd>[/bold] to access the internet.")
    console.print()
    console.print(
        f"[yellow]Note:[/yellow] Open a new shell (or run [bold]newgrp {group}[/bold]) "
        "for group membership to take effect."
    )
    console.print(
        "  Run [bold]sudo space save[/bold] to persist rules across reboots "
        "(requires iptables-persistent)."
    )


# ── on / off ───────────────────────────────────────────────────────────────────

@main.command()
def on():
    """Enable internet blocking (re-apply firewall rules)."""
    require_root()
    config = load_config()
    need_init(config)
    firewall.apply_rules(config["subnets"], config["group"])
    console.print("[green]✓ Internet blocking enabled.[/green]")


@main.command()
def off():
    """Disable internet blocking (flush OUTPUT rules)."""
    require_root()
    config = load_config()
    need_init(config)

    if not Confirm.ask(
        "[yellow]This allows unrestricted internet access. Continue?[/yellow]",
        default=False,
    ):
        return

    firewall.remove_rules()
    console.print("[yellow]✓ Internet blocking disabled. All outbound traffic is now allowed.[/yellow]")


# ── status ─────────────────────────────────────────────────────────────────────

@main.command()
def status():
    """Show current firewall status and configuration."""
    config = load_config()
    initialized = config.get("initialized", False)
    blocking = firewall.is_blocking()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("key", style="dim", no_wrap=True)
    table.add_column("value")

    table.add_row("Initialized", "[green]yes[/green]" if initialized else "[red]no[/red]")
    table.add_row(
        "Blocking internet",
        "[red]yes[/red]" if blocking else "[green]no[/green]",
    )
    table.add_row("LAN subnets", ", ".join(config.get("subnets", [])) or "[dim]-[/dim]")
    table.add_row("Internet group", config.get("group") or "[dim]-[/dim]")
    table.add_row(
        "inet wrapper",
        "[green]/usr/local/bin/inet[/green]" if config.get("wrapper_installed") else "[dim]not installed[/dim]",
    )

    console.print()
    console.print(table)

    if initialized:
        console.print()
        console.print("[dim]iptables OUTPUT chain:[/dim]")
        console.print(firewall.get_rules_text())


# ── run ────────────────────────────────────────────────────────────────────────

@main.command(
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True}
)
@click.argument("command", nargs=-1, required=True)
def run(command):
    """Run a command with internet access.

    \b
    Examples:
      space run curl https://example.com
      space run firefox
      space run -- python my_script.py --flag value
    """
    config = load_config()
    need_init(config)
    firewall.run_with_internet(list(command), config["group"])


# ── internet shell ─────────────────────────────────────────────────────────────

@main.command()
@click.option("--dns", default="8.8.8.8", show_default=True, help="DNS server to use inside the shell.")
@click.option("--shell", "shell_bin", default="/bin/bash", show_default=True, help="Shell binary to launch.")
def shell(dns, shell_bin):
    """Launch a shell with full internet access.

    \b
    All commands inside — including sudo — have internet access.
    The namespace is torn down automatically when you exit the shell.

    Requires sudo to set up the network namespace.
    """
    require_root()
    config = load_config()
    need_init(config)

    username = os.environ.get("SUDO_USER") or os.environ.get("USER")
    if not username or username == "root":
        console.print("[red]Could not determine the real user. Run with sudo.[/red]")
        import sys; sys.exit(1)

    console.print(f"[cyan]Setting up internet namespace...[/cyan]")
    try:
        firewall.setup_internet_namespace(dns=dns)
    except Exception as e:
        console.print(f"[red]Failed to set up namespace:[/red] {e}")
        import sys; sys.exit(1)

    console.print(f"[green]Entering internet shell[/green] [dim](exit to return)[/dim]\n")
    try:
        firewall.run_internet_shell(username, shell=shell_bin)
    finally:
        firewall.teardown_internet_namespace()
    console.print("[dim]Internet namespace torn down.[/dim]")


# ── subnet management ──────────────────────────────────────────────────────────

@main.command()
def subnet():
    """Re-detect or update allowed LAN subnets."""
    require_root()
    config = load_config()
    need_init(config)

    detected = get_local_subnets()
    current = config.get("subnets", [])

    console.print(f"[dim]Current subnets:[/dim] {', '.join(current) or '-'}")
    if detected:
        console.print(f"[green]Detected:[/green]        {', '.join(detected)}")
        use_detected = Confirm.ask("Use detected subnets?", default=True)
    else:
        console.print("[yellow]Could not auto-detect subnets.[/yellow]")
        use_detected = False

    if use_detected:
        subnets = detected
    else:
        raw = Prompt.ask(
            "Enter subnets (comma-separated)",
            default=", ".join(current),
        )
        subnets = [s.strip() for s in raw.split(",") if s.strip()]

    config["subnets"] = subnets
    save_config(config)

    if firewall.is_blocking():
        firewall.apply_rules(subnets, config["group"])
        console.print("[green]✓ Subnets updated and rules re-applied.[/green]")
    else:
        console.print("[green]✓ Subnets updated (rules are currently off).[/green]")


# ── save / persist ─────────────────────────────────────────────────────────────

@main.command()
def save():
    """Persist current iptables rules across reboots via netfilter-persistent."""
    require_root()
    try:
        firewall.save_rules()
        console.print("[green]✓ Rules saved.[/green]")
    except FileNotFoundError:
        console.print(
            "[red]netfilter-persistent not found.[/red] "
            "Install it with: [bold]sudo apt install iptables-persistent[/bold]"
        )
    except Exception as e:
        console.print(f"[red]Failed:[/red] {e}")


# ── panic ──────────────────────────────────────────────────────────────────────

@main.command()
def panic():
    """Emergency: drop all firewall rules and restore full internet access.

    No confirmation prompt — runs immediately.
    """
    require_root()
    for ipt in ("iptables", "ip6tables"):
        subprocess.run([ipt, "-F", "OUTPUT"])
        subprocess.run([ipt, "-P", "OUTPUT", "ACCEPT"])
        subprocess.run([ipt, "-F", "FORWARD"])
        subprocess.run([ipt, "-t", "nat", "-F"])
    console.print("[green]✓ All rules cleared. Full internet access restored.[/green]")


# ── uninstall ──────────────────────────────────────────────────────────────────

@main.command()
def uninstall():
    """Remove all space firewall rules and the inet wrapper."""
    require_root()

    if not Confirm.ask(
        "[red]Remove all space firewall rules and the inet wrapper?[/red]",
        default=False,
    ):
        return

    firewall.remove_rules()
    console.print("[green]✓ Firewall rules removed.[/green]")

    firewall.remove_wrapper()
    console.print("[green]✓ Removed /usr/local/bin/inet.[/green]")

    config = load_config()
    username = config.get("username") or os.environ.get("SUDO_USER") or os.environ.get("USER")
    if username and remove_shell_alias(username):
        console.print("[green]✓ Removed shell alias.[/green]")

    console.print("[dim]Config preserved at ~/.config/space/config.json[/dim]")
    console.print("[dim]Group 'internet' preserved (remove manually with: sudo groupdel internet)[/dim]")
