from __future__ import annotations

import sys

from cli import (
    cmd_analyze,
    cmd_dead,
    cmd_explain,
    cmd_flag,
    cmd_graph,
    cmd_index,
    cmd_object,
    cmd_plot,
    cmd_report,
    cmd_room,
    cmd_script,
    cmd_search,
)


def main() -> int:
    args = sys.argv[1:]
    if not args:
        cmd_explain([])
        return 0

    command = args[0]
    rest = args[1:]

    dispatch = {
        "index": cmd_index,
        "analyze": cmd_analyze,
        "graph": cmd_graph,
        "report": cmd_report,
        "object": cmd_object,
        "room": cmd_room,
        "script": cmd_script,
        "flag": cmd_flag,
        "plot": cmd_plot,
        "dead": cmd_dead,
        "search": cmd_search,
        "help": cmd_explain,
    }

    handler = dispatch.get(command)
    if handler is None:
        print(f"Unknown command: {command}", file=sys.stderr)
        print("Use 'help' for available commands", file=sys.stderr)
        return 1

    if command in ("object", "room", "script", "flag"):
        if len(rest) < 1:
            print(f"Error: '{command}' requires a name argument", file=sys.stderr)
            return 1
        name = rest[0]
        path_args = rest[1:]
        if not path_args:
            print(f"Error: '{command}' requires a project path", file=sys.stderr)
            return 1
        return handler(name, path_args)

    if command in ("search",):
        if len(rest) < 1:
            print(f"Error: '{command}' requires a pattern argument", file=sys.stderr)
            return 1
        pattern = rest[0]
        path_args = rest[1:]
        if not path_args:
            print(f"Error: '{command}' requires a project path", file=sys.stderr)
            return 1
        return handler(pattern, path_args)

    if command in ("index", "analyze", "graph", "report", "plot", "dead"):
        if not rest:
            print(f"Error: '{command}' requires a project path", file=sys.stderr)
            return 1
        return handler(rest[0], rest[1:])

    return handler(rest)


if __name__ == "__main__":
    sys.exit(main())
