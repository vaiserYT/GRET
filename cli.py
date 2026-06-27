from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from binary.all_chunks import load_game
from ir.graph import ResourceGraph
from analysis.secret import SuspiciousItem
from query.engine import QueryEngine
from ir.validate import validate_all, print_validation_results


console = Console()


def _progress_bar(description="Working..."):
    return Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
        transient=True,
    )


def cmd_load(path: Path) -> tuple:
    game = load_game(path)
    summary = game.summary()
    console.print(f"[green]Loaded {summary['objects']} objects, {summary['rooms']} rooms, "
                  f"{summary['scripts']} scripts, {summary['sprites']} sprites, "
                  f"{summary['sounds']} sounds, {summary['strings']} strings[/]")
    console.print(f"[dim]  + {summary['functions']} functions, {summary['variables']} variables, "
                  f"{summary['code_entries']} code entries, {summary['texture_pages']} texture pages[/]")
    console.print("[yellow]Building graphs...[/]")
    graph = ResourceGraph(game, game.resolver)
    graph.build_all()
    game.rgraph = graph
    engine = QueryEngine(game, graph)
    console.print("[green]Ready for queries.[/]")
    return game, graph, engine


def cmd_index(game_path: Path) -> None:
    game, graph, engine = cmd_load(game_path)


def cmd_analyze(game_path: Path) -> None:
    game, graph, engine = cmd_load(game_path)
    with _progress_bar("Running full analysis...") as progress:
        task = progress.add_task("Analyzing objects...", total=8)
        def cb(c, t, msg):
            progress.update(task, completed=c, total=t, description=msg)
        secrets = engine.hidden_resources(on_progress=cb)
    table = Table(title="Top Suspicious Items")
    table.add_column("Score", style="red", no_wrap=True)
    table.add_column("Type", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Reasons", style="white")

    for item in secrets[:50]:
        reasons = "; ".join(item.reasons[:2])
        if len(item.reasons) > 2:
            reasons += f" (+{len(item.reasons)-2})"
        table.add_row(str(item.confidence), item.resource_type, item.name, reasons)

    console.print(table)
    console.print(f"\n[bold]Total suspicious:[/] {len(secrets)}")
    console.print(f"[yellow]Unreachable rooms:[/] {len(engine.unreachable_rooms())}")
    console.print(f"[yellow]Dead objects:[/] {len(engine.dead_objects())}")
    console.print(f"[yellow]Unused dialogue:[/] {len(engine.unreachable_dialogue())}")


def cmd_why_object(args: list[str], game, graph, engine) -> None:
    if not args:
        console.print("[red]Usage: why <object_name>[/]")
        return
    name = args[0]
    with _progress_bar("Analyzing object usage...") as progress:
        task = progress.add_task("Analyzing runtime usage...", total=11)
        def cb(c, t, msg):
            progress.update(task, completed=c, total=t, description=msg)
        info = engine.why_object(name, on_progress=cb)
    if "error" in info:
        console.print(f"[red]{info['error']}[/]")
        return

    console.print(f"[bold cyan]Object:[/] {info['name']} (id={info['id']})")
    console.print(f"  Sprite: {info['sprite'] or 'None'}")
    console.print(f"  Parent: {info['parent'] or 'None'}")
    console.print(f"  Depth: {info['depth']}, Persistent: {info['persistent']}")
    
    if info['placed_in_rooms']:
        console.print(f"  [green]Placed in rooms:[/]")
        for r in info['placed_in_rooms']:
            console.print(f"    - {r}")
    else:
        console.print(f"  [yellow]Not placed in any room[/]")

    if info['created_dynamically_by']:
        console.print(f"  [green]Created dynamically by:[/]")
        for c in info['created_dynamically_by']:
            console.print(f"    - {c}")
    
    if info['events']:
        console.print(f"  Events: {len(info['events'])}")
        for et, sub in info['events']:
            console.print(f"    - event[{et}]({sub})")
    else:
        console.print(f"  [yellow]No events[/]")

    if info['incoming_refs']:
        console.print(f"  Referenced by: {', '.join(info['incoming_refs'][:10])}")
    if info['outgoing_refs']:
        console.print(f"  References: {', '.join(info['outgoing_refs'][:10])}")


def cmd_trace(args: list[str], game, graph, engine) -> None:
    if not args:
        console.print("[red]Usage: trace <pattern>[/]")
        return
    with _progress_bar("Searching all resources...") as progress:
        task = progress.add_task("Analyzing objects...", total=6)
        def cb(c, t, msg):
            progress.update(task, completed=c, total=t, description=msg)
        results = engine.trace(args[0], on_progress=cb)
    if not results:
        console.print(f"[yellow]No results for '{args[0]}'[/]")
        return
    table = Table(title=f"Trace results for '{args[0]}'")
    table.add_column("Type", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Summary", style="white")
    for r in results[:30]:
        table.add_row(r.get("type", "?"), r.get("name", "?"), r.get("summary", ""))
    console.print(table)


def cmd_who_uses(args: list[str], game, graph, engine) -> None:
    if not args:
        console.print("[red]Usage: who_uses <resource_name>[/]")
        return
    with _progress_bar("Finding references...") as progress:
        task = progress.add_task("Analyzing...", total=4)
        def cb(c, t, msg):
            progress.update(task, completed=c, total=t, description=msg)
        result = engine.who_uses(args[0], on_progress=cb)
    total = sum(len(v) for v in result.values())
    if total == 0:
        console.print(f"[yellow]No users found for '{args[0]}'[/]")
        return
    console.print(f"[green]Users of '{args[0]}' ({total}):[/]")
    for category, items in result.items():
        if not items:
            continue
        label = category.replace("_", " ").title()
        console.print(f"  [cyan]{label}:[/]")
        for item in items[:10]:
            console.print(f"    - {item}")
        if len(items) > 10:
            console.print(f"    ... and {len(items) - 10} more")


def cmd_flag(args: list[str], game, graph, engine) -> None:
    if not args:
        console.print("[red]Usage: flag <index>[/]")
        return
    try:
        idx = int(args[0])
    except ValueError:
        console.print("[red]Flag index must be an integer[/]")
        return
    writers = engine.who_writes_flag(idx)
    console.print(f"[bold cyan]Flag {idx}[/]")
    if writers:
        console.print(f"  Written by: {', '.join(writers)}")
    else:
        console.print(f"  [yellow]Never written (or couldn't detect via strings)[/]")


def cmd_show_room(args: list[str], game, graph, engine) -> None:
    if not args:
        console.print("[red]Usage: show_room <room_name>[/]")
        return
    info = engine.show_room(args[0])
    if "error" in info:
        console.print(f"[red]{info['error']}[/]")
        return
    console.print(f"[bold cyan]Room:[/] {info['name']}")
    console.print(f"  Size: {info['size']}, Speed: {info['speed']}")
    console.print(f"  Persistent: {info['persistent']}, Reachable: {info['reachable']}")
    console.print(f"  Views: {info['view_count']}, Backgrounds: {info['background_count']}")
    console.print(f"  Instances ({len(info['instances'])}):")
    for inst in info['instances'][:30]:
        cc = " [dim](creation code)[/]" if inst['has_creation_code'] else ""
        console.print(f"    - {inst['object']} @ ({inst['x']}, {inst['y']}){cc}")
    if len(info['instances']) > 30:
        console.print(f"    ... and {len(info['instances']) - 30} more")
    if info.get('incoming_transitions'):
        console.print(f"  Incoming: {', '.join(info['incoming_transitions'][:10])}")
    if info.get('outgoing_transitions'):
        console.print(f"  Outgoing: {', '.join(info['outgoing_transitions'][:10])}")


def cmd_unreachable(game, graph, engine) -> None:
    rooms = engine.unreachable_rooms()
    console.print(f"[bold yellow]Unreachable Rooms ({len(rooms)}):[/]")
    for r in rooms[:50]:
        console.print(f"  - {r}")
    if len(rooms) > 50:
        console.print(f"  ... and {len(rooms) - 50} more")

    with _progress_bar("Analyzing dialogue...") as progress:
        task = progress.add_task("Scanning for unused dialogue...", total=None)
        def cb1(c, t, msg):
            if task.total is None and t > 0:
                progress.update(task, total=t)
            progress.update(task, completed=c, description=msg)
        dialogue = engine.unreachable_dialogue(on_progress=cb1)
    console.print(f"\n[bold yellow]Unused Dialogue ({len(dialogue)}):[/]")
    for sid, text in dialogue[:30]:
        console.print(f"  - {sid}: \"{text}\"")
    if len(dialogue) > 30:
        console.print(f"  ... and {len(dialogue) - 30} more")

    with _progress_bar("Analyzing dead objects...") as progress:
        task = progress.add_task("Scanning object usage...", total=11)
        def cb2(c, t, msg):
            progress.update(task, completed=c, total=t, description=msg)
        dead = engine.dead_objects(on_progress=cb2)
    console.print(f"\n[bold yellow]Dead Objects ({len(dead)}):[/]")
    for d in dead[:50]:
        console.print(f"  - {d}")
    if len(dead) > 50:
        console.print(f"  ... and {len(dead) - 50} more")


def cmd_secret(game, graph, engine) -> None:
    with _progress_bar("Finding hidden resources...") as progress:
        task = progress.add_task("Analyzing objects...", total=8)
        def cb(c, t, msg):
            progress.update(task, completed=c, total=t, description=msg)
        secrets = engine.hidden_resources(on_progress=cb)
    table = Table(title=f"Hidden Resources / Secrets ({len(secrets)} total)")
    table.add_column("Score", style="red", no_wrap=True)
    table.add_column("Type", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Reasons", style="white")
    table.add_column("Details", style="dim")

    for item in secrets[:100]:
        reasons = "; ".join(item.reasons[:2])
        details = item.details[:60] if item.details else ""
        table.add_row(str(item.confidence), item.resource_type, item.name, reasons, details)

    console.print(table)


def cmd_search(args: list[str], game, graph, engine) -> None:
    if not args:
        console.print("[red]Usage: search <pattern>[/]")
        return
    with _progress_bar("Searching...") as progress:
        task = progress.add_task("Scanning resources...", total=6)
        def cb(c, t, msg):
            progress.update(task, completed=c, total=t, description=msg)
        results = engine.search(args[0], on_progress=cb)
    if not results:
        console.print(f"[yellow]No matches for '{args[0]}'[/]")
        return
    table = Table(title=f"Search results for '{args[0]}'")
    table.add_column("Type", style="cyan")
    table.add_column("Name/ID", style="green")
    table.add_column("Info", style="white")
    for r in results[:50]:
        table.add_row(r.get("type", ""), str(r.get("name", r.get("id", ""))), r.get("summary", ""))
    console.print(table)


def cmd_summary(args: list[str], game, graph, engine) -> None:
    s = game.summary()
    gs = graph.room_graph_summary()
    table = Table(title="Game Summary")
    table.add_column("Resource", style="cyan")
    table.add_column("Count", style="green")
    for key, label in [
        ("objects", "Objects"), ("rooms", "Rooms"), ("scripts", "Scripts"),
        ("sprites", "Sprites"), ("sounds", "Sounds"), ("fonts", "Fonts"),
        ("timelines", "Timelines"), ("paths", "Paths"),
        ("functions", "Functions"), ("variables", "Variables"),
        ("code_entries", "Code Entries"), ("strings", "Strings"),
        ("texture_pages", "Texture Pages"),
    ]:
        table.add_row(label, str(s.get(key, 0)))
    table.add_row("Room Graph Nodes", str(gs["nodes"]))
    table.add_row("Room Graph Edges", str(gs["edges"]))
    table.add_row("Unreachable Rooms", str(len(gs.get("unreachable", []))))
    console.print(table)


def cmd_graph(args: list[str], game, graph, engine) -> None:
    gs = graph.room_graph_summary()
    cs = graph.call_graph_summary()
    console.print("[bold]Graph Statistics:[/]")
    console.print(f"  Room graph: {gs['nodes']} nodes, {gs['edges']} edges, {gs['components']} components")
    console.print(f"  Call graph: {cs['nodes']} nodes, {cs['edges']} edges")
    console.print(f"  Object graph: {graph.object.number_of_nodes()} nodes")
    unreachable_names = [game.room_by_id(r).name if game.room_by_id(r) else f"room_{r}" for r in gs['unreachable']]
    console.print(f"  Unreachable rooms: {len(gs['unreachable'])}")
    if unreachable_names:
        console.print(f"    [yellow]{', '.join(unreachable_names[:10])}[/]")


def cmd_interactive(game_path: Path, game=None, graph=None, engine=None) -> None:
    if game is None:
        game, graph, engine = cmd_load(game_path)
    console.print()
    console.print(Panel.fit("[bold cyan]GameMaker Reverse Engineering Toolkit[/]\n"
                           "Type 'help' for commands, 'quit' to exit.", border_style="cyan"))

    commands = {
        "help": lambda args: cmd_help(),
        "summary": lambda args: cmd_summary(args, game, graph, engine),
        "graph": lambda args: cmd_graph(args, game, graph, engine),
        "why": lambda args: cmd_why_object(args, game, graph, engine),
        "trace": lambda args: cmd_trace(args, game, graph, engine),
        "who_uses": lambda args: cmd_who_uses(args, game, graph, engine),
        "who": lambda args: cmd_who_uses(args, game, graph, engine),
        "flag": lambda args: cmd_flag(args, game, graph, engine),
        "room": lambda args: cmd_show_room(args, game, graph, engine),
        "show_room": lambda args: cmd_show_room(args, game, graph, engine),
        "unreachable": lambda args: cmd_unreachable(game, graph, engine),
        "secret": lambda args: cmd_secret(game, graph, engine),
        "search": lambda args: cmd_search(args, game, graph, engine),
        "debug_resolver": lambda args: cmd_debug_resolver(args, game),
        "debug_graph": lambda args: cmd_debug_graph(args, game),
        "debug_chunks": lambda args: cmd_debug_chunks(args, game),
    }

    while True:
        try:
            line = input("gm> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Bye![/]")
            break

        if not line:
            continue
        if line == "quit" or line == "exit":
            break

        parts = line.split()
        cmd = parts[0].lower()
        args_list = parts[1:]

        handler = commands.get(cmd)
        if handler:
            handler(args_list)
        else:
            console.print(f"[red]Unknown command: {cmd}. Type 'help'.[/]")


def cmd_debug_resolver(args, game=None, graph=None, engine=None) -> None:
    r = getattr(game, 'resolver', None) if game else None
    if r is None:
        console.print("[red]No resolver data available. Call load_game() first.[/]")
        return
    results = validate_all(game)
    print_validation_results(results, show_info=False)


def cmd_debug_graph(args, game=None, graph=None, engine=None) -> None:
    r = getattr(game, 'resolver', None) if game else None
    rg = getattr(game, 'rgraph', None) if game else None
    if r is None or rg is None:
        console.print("[red]No resolver/graph data. Call load_game() first.[/]")
        return
    results = validate_all(game)
    graph_issues = results.get("graphs", [])
    console.print("[bold cyan]GRAPH VALIDATION[/]")
    for i in graph_issues:
        tag = {"error": "[red]ERROR[/]", "warning": "[yellow]WARN[/]", "info": "[dim]INFO[/]"}
        console.print(f"  {tag.get(i.severity, '?')}  {i.message}")

    console.print("\n[bold]Graph structure:[/]")
    console.print(f"  Room graph: {rg.room.number_of_nodes()} nodes, {rg.room.number_of_edges()} edges")
    console.print(f"  Call graph: {rg.call.number_of_nodes()} nodes, {rg.call.number_of_edges()} edges")
    console.print(f"  Object graph: {rg.object.number_of_nodes()} nodes, {rg.object.number_of_edges()} edges")
    unreachable = rg.unreachable_rooms()
    if unreachable:
        names = []
        for rid in sorted(unreachable)[:20]:
            r = game.room_by_id(rid)
            names.append(r.name if r else f"room_{rid}")
        console.print(f"  [yellow]Unreachable rooms ({len(unreachable)}): {', '.join(names)}[/]")


def cmd_debug_chunks(args, game=None, graph=None, engine=None) -> None:
    if game is None:
        console.print("[red]No game data. Call load_game() first.[/]")
        return
    results = validate_all(game)
    chunk_issues = results.get("chunks", [])
    console.print("[bold cyan]CHUNK VALIDATION[/]")
    tag_map = {"error": "[red]ERROR[/]", "warning": "[yellow]WARN[/]", "info": "[dim]INFO[/]"}
    for i in chunk_issues:
        console.print(f"  {tag_map.get(i.severity, '?')}  {i.message}")

    console.print("\n[bold]Chunk statistics:[/]")
    console.print(f"  OBJT: {len(game.objects)} objects")
    console.print(f"  ROOM: {len(game.rooms)} rooms")
    console.print(f"  SPRT: {len(game.sprites)} sprites")
    console.print(f"  SOND: {len(game.sounds)} sounds")
    console.print(f"  FONT: {len(game.fonts)} fonts")
    console.print(f"  CODE: {len(game.code_entries)} entries")
    console.print(f"  FUNC: {len(game.functions)} functions")
    console.print(f"  VARI: {len(game.variables)} variables")
    console.print(f"  STRG: {len(game.strings)} strings")


def cmd_help() -> None:
    console.print(Panel.fit(
        "[bold cyan]Commands:[/]\n\n"
        "  summary           Show game resource summary\n"
        "  graph             Show graph statistics\n"
        "  why <object>      Why does this object exist?\n"
        "  trace <pattern>   Trace a pattern across all resources\n"
        "  who_uses <res>    Who references this resource?\n"
        "  flag <index>      Who writes to this flag?\n"
        "  room <name>       Show room details\n"
        "  unreachable       Show unreachable rooms, dialogue, objects\n"
        "  secret            Find hidden/suspicious resources\n"
        "  search <pattern>  Search resources by name pattern\n"
        "  debug_resolver    Run comprehensive validator on resolver\n"
        "  debug_graph       Run comprehensive validator on graphs\n"
        "  debug_chunks      Run comprehensive validator on chunks\n"
        "  help              Show this help\n"
        "  quit              Exit\n\n"
        "[dim]Examples:[/]\n"
        "  why obj_ch5_LW21\n"
        "  trace LW21\n"
        "  trace side_b\n"
        "  who_uses spr_kris_rise_side_b\n"
        "  flag 1767\n"
        "  room room_town_north\n"
        "  secret",
        title="Help",
        border_style="cyan",
    ))


def main() -> int:
    args = sys.argv[1:]

    if not args:
        cmd_help()
        return 0

    command = args[0].lower()
    rest = args[1:]

    if command == "help":
        cmd_help()
        return 0

    if command == "index":
        if not rest:
            console.print("[red]Usage: index <data.win>[/]")
            return 1
        cmd_index(Path(rest[0]))
        return 0

    if command == "analyze":
        if not rest:
            console.print("[red]Usage: analyze <data.win>[/]")
            return 1
        cmd_analyze(Path(rest[0]))
        return 0

    if command == "interactive" or command == "shell" or command == "i":
        if not rest:
            console.print("[red]Usage: interactive <data.win>[/]")
            return 1
        cmd_interactive(Path(rest[0]))
        return 0

    path = Path(args[0])
    if not path.exists():
        console.print(f"[red]File not found: {path}[/]")
        console.print("Usage: python analyzer.py <data.win> [command]")
        return 1

    game, graph, engine = cmd_load(path)

    if len(args) == 1:
        cmd_interactive(path, game, graph, engine)
    else:
        command = args[1].lower()
        cmd_rest = args[2:]
        dispatch = {
            "summary": cmd_summary,
            "graph": cmd_graph,
            "why": cmd_why_object,
            "trace": cmd_trace,
            "who_uses": cmd_who_uses,
            "who": cmd_who_uses,
            "flag": cmd_flag,
            "room": cmd_show_room,
            "show_room": cmd_show_room,
            "unreachable": cmd_unreachable,
            "secret": cmd_secret,
            "search": cmd_search,
            "analyze": cmd_analyze,
            "debug_resolver": cmd_debug_resolver,
            "debug_graph": cmd_debug_graph,
            "debug_chunks": cmd_debug_chunks,
        }
        handler = dispatch.get(command)
        if handler:
            handler(cmd_rest, game, graph, engine)
        else:
            console.print(f"[red]Unknown command: {command}[/]")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
