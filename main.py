from __future__ import annotations

import sys
from pathlib import Path

from cli import cmd_load, cmd_analyze
from cli import cmd_graph, cmd_summary
from cli import cmd_unreachable, cmd_secret, cmd_search
from cli import cmd_flag, cmd_debug_resolver, cmd_debug_graph, cmd_debug_chunks


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print("Usage: python main.py <command> <game_path> [opts...]")
        print("Commands: analyze, graph, summary, unreachable, secret, search,"
              " flag, debug_resolver, debug_graph, debug_chunks")
        return 0

    command = args[0]
    rest = args[1:]

    if command == "help":
        return 0

    # Commands that load the game themselves
    if command == "analyze":
        if not rest:
            print("Usage: analyze <game_path>", file=sys.stderr)
            return 1
        return cmd_analyze(Path(rest[0]))

    if command == "index":
        if not rest:
            print("Usage: index <game_path>", file=sys.stderr)
            return 1
        return cmd_load(Path(rest[0]))

    # All other commands need game loaded first
    if not rest:
        print(f"Usage: {command} <game_path> [args...]", file=sys.stderr)
        return 1

    path = Path(rest[0])
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        return 1

    try:
        game, graph, engine = cmd_load(path)
    except Exception as e:
        print(f"Error loading game: {e}", file=sys.stderr)
        return 1

    cmd_rest = rest[1:]

    dispatch = {
        "graph": lambda: cmd_graph(cmd_rest, game, graph, engine),
        "summary": lambda: cmd_summary(cmd_rest, game, graph, engine),
        "unreachable": lambda: cmd_unreachable(game, graph, engine),
        "secret": lambda: cmd_secret(game, graph, engine),
        "search": lambda: cmd_search(cmd_rest, game, graph, engine),
        "flag": lambda: cmd_flag(cmd_rest, game, graph, engine),
        "debug_resolver": lambda: cmd_debug_resolver(cmd_rest, game),
        "debug_graph": lambda: cmd_debug_graph(cmd_rest, game),
        "debug_chunks": lambda: cmd_debug_chunks(cmd_rest, game),
    }

    handler = dispatch.get(command)
    if handler is None:
        print(f"Unknown command: {command}", file=sys.stderr)
        return 1

    try:
        handler()
    except Exception as e:
        print(f"Error in {command}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
