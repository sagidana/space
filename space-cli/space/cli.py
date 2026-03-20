import os
import shutil
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import firewall
from .config import load as load_config, save as save_config
from .network import get_local_subnets, get_system_dns

console = Console()


# ── helpers ────────────────────────────────────────────────────────────────────

def ensure_root():
    """Re-execute the current command under sudo if not already root."""
    if os.geteuid() == 0:
        return
    console.print("[yellow]Root privileges required. Re-running with sudo...[/yellow]")
    argv0 = shutil.which(sys.argv[0]) or sys.argv[0]
    try:
        os.execvp("sudo", ["sudo", "-E", argv0] + sys.argv[1:])
    except Exception as e:
        console.print(f"[red]Failed to escalate to root:[/red] {e}")
        sys.exit(1)


def need_init(config):
    if not config.get("initialized"):
        console.print(
            "[yellow]space is not initialized. Run [bold]sudo space init[/bold] first.[/yellow]"
        )
        sys.exit(1)



# ── CLI ────────────────────────────────────────────────────────────────────────

class _DefaultRunGroup(click.Group):
    """Treat unknown subcommands as arguments to `run`."""
    def parse_args(self, ctx, args):
        if args and not args[0].startswith("-") and args[0] not in self.commands:
            args = ["run"] + list(args)
        return super().parse_args(ctx, args)


@click.group(cls=_DefaultRunGroup)
def main():
    """space — make internet access explicit, not implicit."""


# ── init ───────────────────────────────────────────────────────────────────────

@main.command()
def init():
    """First-time setup: detect subnet, create group, apply firewall rules."""
    ensure_root()
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

    # ── DNS detection ─────────────────────────────────────────────────────────
    detected_dns = get_system_dns()
    if detected_dns:
        console.print(f"[green]Detected system DNS:[/green] {detected_dns}")
    else:
        console.print("[yellow]Could not auto-detect system DNS. Falling back to 8.8.8.8.[/yellow]")
        detected_dns = "8.8.8.8"
    dns = Prompt.ask("DNS server for internet namespace", default=detected_dns)

    # ── group name ────────────────────────────────────────────────────────────
    group = Prompt.ask("Internet-access group name", default="internet")

    # real user (when invoked via sudo)
    username = os.environ.get("SUDO_USER") or os.environ.get("USER")

    # ── confirm ───────────────────────────────────────────────────────────────
    console.print()
    console.print("[bold]Summary[/bold]")
    real_bin = Path(shutil.which(sys.argv[0]) or sys.argv[0]).resolve()
    console.print(f"  LAN subnets  : {', '.join(subnets)}")
    console.print(f"  DNS          : {dns}")
    console.print(f"  Group        : {group}")
    console.print(f"  Add user     : {username or '(unknown)'}")
    console.print(f"  Wrapper      : /usr/local/bin/inet")
    console.print(f"  Symlink      : /usr/bin/space → {real_bin}")
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
        "dns": dns,
        "group": group,
        "initialized": True,
        "wrapper_installed": True,
        "username": username,
    })
    save_config(config)
    console.print("[green]✓[/green] Saved config to ~/.config/space/config.json")

    # ── symlink to /usr/bin for system-wide sudo access ──────────────────────
    symlink = Path("/usr/bin/space")
    try:
        if symlink.is_symlink() or symlink.exists():
            symlink.unlink()
        symlink.symlink_to(real_bin)
        console.print(f"[green]✓[/green] Symlinked [bold]{symlink}[/bold] → [bold]{real_bin}[/bold]")
    except Exception as e:
        console.print(f"[yellow]![/yellow] Could not create /usr/bin/space symlink: {e}")

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
    ensure_root()
    config = load_config()
    need_init(config)
    firewall.apply_rules(config["subnets"], config["group"])
    console.print("[green]✓ Internet blocking enabled.[/green]")


@main.command()
def off():
    """Disable internet blocking (flush OUTPUT rules)."""
    ensure_root()
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
    table.add_row("Namespace DNS", config.get("dns") or "[dim]-[/dim]")
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

@main.command(
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True}
)
@click.option("--dns", default=None, help="DNS server to use inside the shell (overrides saved config).")
@click.option("--shell", "shell_bin", default="/bin/bash", show_default=True, help="Shell binary to launch.")
@click.argument("command", nargs=-1)
def shell(dns, shell_bin, command):
    """Launch an internet shell, or run a command in the internet namespace.

    \b
    Without arguments: opens an interactive shell with full internet access.
    With arguments: runs the command in the background inside the namespace.
      The namespace stays alive until the process exits or you kill the session.

    \b
    Examples:
      space shell                   # interactive shell
      space shell firefox           # launch firefox with internet access
      space shell git push          # run git push with internet access
    """
    ensure_root()
    config = load_config()
    need_init(config)

    if dns is None:
        dns = config.get("dns") or "8.8.8.8"

    username = os.environ.get("SUDO_USER") or os.environ.get("USER")
    if not username or username == "root":
        console.print("[red]Could not determine the real user.[/red]")
        sys.exit(1)

    console.print(f"[cyan]Setting up internet namespace...[/cyan]")
    try:
        firewall.setup_internet_namespace(dns=dns)
    except Exception as e:
        console.print(f"[red]Failed to set up namespace:[/red] {e}")
        sys.exit(1)

    if command:
        cmd_list = list(command)
        pid = firewall.run_internet_command_background(username, cmd_list)
        session_id = firewall.register_session(pid, cmd_list)
        console.print(
            f"[green]Session {session_id}[/green] started: "
            f"[bold]{' '.join(cmd_list)}[/bold] [dim](pid {pid})[/dim]"
        )
        console.print(
            f"[dim]  space shells          — list sessions[/dim]\n"
            f"[dim]  space kill {session_id:<3}         — stop this session[/dim]"
        )
    else:
        console.print(f"[green]Entering internet shell[/green] [dim](exit to return)[/dim]")
        console.print(
            f"[dim]  Docker: use [bold]--network {firewall.DOCKER_NETWORK_NAME}[/bold] "
            f"to give a container internet access[/dim]\n"
        )
        proc = firewall.run_internet_shell(username, shell=shell_bin)
        session_id = firewall.register_session(proc.pid, [shell_bin])
        try:
            proc.wait()
        finally:
            firewall.unregister_session(session_id)
            if firewall.teardown_internet_namespace():
                console.print("[dim]Internet namespace torn down.[/dim]")


# ── session management ─────────────────────────────────────────────────────────

@main.command("shells")
def shells():
    """List all active internet namespace sessions."""
    ensure_root()
    sessions = firewall.list_sessions()
    if not sessions:
        console.print("[dim]No active sessions.[/dim]")
        return

    table = Table(show_header=True)
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("PID", style="dim", no_wrap=True)
    table.add_column("Command")
    table.add_column("Started", style="dim", no_wrap=True)

    for s in sessions:
        table.add_row(
            str(s["id"]),
            str(s["pid"]),
            " ".join(s["command"]),
            s.get("started", "-"),
        )

    console.print(table)


@main.command("kill")
@click.argument("session_id", type=int)
def kill_cmd(session_id):
    """Kill a specific internet namespace session by ID."""
    ensure_root()
    success, message = firewall.kill_session(session_id)
    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        console.print(f"[red]✗[/red] {message}")
        sys.exit(1)


@main.command("killall")
def killall():
    """Kill all active internet namespace sessions."""
    ensure_root()
    sessions = firewall.list_sessions()
    if not sessions:
        console.print("[dim]No active sessions.[/dim]")
        return

    killed = 0
    for s in sessions:
        success, message = firewall.kill_session(s["id"])
        if success:
            console.print(f"[green]✓[/green] {message}")
            killed += 1
        else:
            console.print(f"[yellow]![/yellow] {message}")

    console.print(f"\n[green]Killed {killed} session(s).[/green]")


# ── subnet management ──────────────────────────────────────────────────────────

@main.command()
def subnet():
    """Re-detect or update allowed LAN subnets."""
    ensure_root()
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
    ensure_root()
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
    ensure_root()
    firewall.remove_rules()
    console.print("[green]✓ All rules cleared. Full internet access restored.[/green]")


# ── uninstall ──────────────────────────────────────────────────────────────────

@main.command()
def uninstall():
    """Remove all space firewall rules and the inet wrapper."""
    ensure_root()

    if not Confirm.ask(
        "[red]Remove all space firewall rules and the inet wrapper?[/red]",
        default=False,
    ):
        return

    firewall.remove_rules()
    console.print("[green]✓ Firewall rules removed.[/green]")

    firewall.remove_wrapper()
    console.print("[green]✓ Removed /usr/local/bin/inet.[/green]")

    symlink = Path("/usr/bin/space")
    if symlink.is_symlink():
        symlink.unlink()
        console.print("[green]✓ Removed /usr/bin/space symlink.[/green]")

    console.print("[dim]Config preserved at ~/.config/space/config.json[/dim]")
    console.print("[dim]Group 'internet' preserved (remove manually with: sudo groupdel internet)[/dim]")
