# GRET

**GameMaker Reverse Engineering Toolkit**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](pyproject.toml)

GRET is a static analysis toolkit for GameMaker games. It parses `data.win` binaries, resolves internal references, builds dependency graphs, and provides a query interface for understanding game internals. Designed for researchers, modders, and developers who need to understand how a GameMaker game works without running it.

---

## Features

**Current**

- Full `data.win` binary parser for all major chunks (OBJT, ROOM, SPRT, SOND, STRG, CODE, FUNC, VARI, FONT, TMLN, PATH, SHDR, SEQU, BGND, DAFL, SCPT)
- Resource database with cross-referenced object, room, sprite, sound, and code entries
- GMS2.3 event parsing — correctly handles the two-level pointer-list event format with 56-byte action structures
- Reference resolver — maps every CODE entry to its owning object, script, room, or global function
- Call graph — directed graph of all script/function call relationships with deduplicated edges
- Room graph — room connectivity derived from object instance sharing
- Object graph — inheritance chains, room placements, instance relationships, and sprite usage
- Bytecode decoder — instruction-level decompilation of GML bytecode
- Hidden content discovery — detects unused rooms, dead objects, orphaned dialogue, and suspicious resources
- Flag reference tracking — identifies flag variable reads and writes across the codebase
- String reference tracking — maps every string literal to its callers
- Interactive CLI — query and explore the game in real time
- Rich terminal output — formatted tables, trees, and color-coded results via the `rich` library

---

## Philosophy

GRET is not a GameMaker editor. It does not modify `data.win`, decompile scripts to editable source, or rebuild assets.

GRET is a reverse engineering toolkit. Its purpose is to help you understand how a GameMaker game works by revealing structure, dependencies, and hidden content. If UndertaleModTool answers "what is this resource?", GRET answers "why does this resource exist, who uses it, and what happens if I remove it?"

---

## Installation

Requires Python 3.12 or later.

```bash
pip install -r requirements.txt
```

Or install with pip:

```bash
pip install .
```

Dependencies: `networkx` (graphs), `orjson` (fast JSON), `rich` (terminal UI), `jinja2` (report templates), `graphviz` (optional, for graph export).

---

## Quick Start

```bash
python cli.py path/to/data.win
```

GRET loads the game, parses all chunks, resolves cross-references, and opens an interactive shell:

```
Loaded 1733 objects, 252 rooms, 0 scripts, 8522 sprites, 764 sounds, 93214 strings
  + 209 functions, 38069 variables, 18025 code entries, 0 texture pages
Building graphs...
Ready for queries.

╭────────────────────────────────────────────╮
│       GameMaker Reverse Engineering Toolkit │
│ Type 'help' for commands, 'quit' to exit.  │
╰────────────────────────────────────────────╯

gm>
```

You can also run commands non-interactively:

```bash
python cli.py path/to/data.win summary
python cli.py path/to/data.win why obj_ch5_LW21
python cli.py path/to/data.win room room_town_north
```

---

## CLI Commands

| Command | Description |
|---|---|
| `summary` | Show aggregate resource counts |
| `graph` | Show graph statistics (room, call, object) |
| `why <object>` | Explain why an object exists — where it's placed, who creates it, what references it |
| `trace <pattern>` | Trace a name or pattern across all resource types |
| `who_uses <resource>` | List all code entries that reference a resource by name |
| `flag <index>` | Show which code entries read or write a specific flag variable |
| `room <name>` | Show room details, instance placements, and transitions |
| `unreachable` | Enumerate unreachable rooms, unused dialogue, and dead objects |
| `secret` | Score and list suspicious/hidden resources |
| `search <pattern>` | Search all resource names by substring |
| `debug_resolver` | Run the full cross-reference validator |
| `debug_graph` | Run the full graph consistency validator |
| `debug_chunks` | Run the full binary parser validator |
| `help` | Display command reference |
| `quit` | Exit the shell |

---

## Examples

### Why does an object exist?

```
gm> why obj_ch5_LW21

Object: obj_ch5_LW21 (id=1421)
  Sprite: spr_lw_21_far
  Parent: obj_ch5_room
  Depth: 100, Persistent: False
  Placed in rooms:
    - room_ch5_lw_21 (248, 240)
    - room_ch5_lw_21_b (256, 12)
  Created dynamically by:
    - obj_ch5_game.event_0_0
  Events: 3
    - event[0](0)
    - event[3](0)
    - event[3](2)
  Referenced by: sprite, room x2, parent
```

### Room details

```
gm> room room_town_north

Room: room_town_north
  Size: 960x832, Speed: 30
  Persistent: True, Reachable: True
  Views: 8, Backgrounds: 1
  Instances (42):
    - obj_player @ (480, 720) (creation code)
    - obj_door_entrance @ (480, 800)
    - obj_npc_shopkeeper @ (280, 640)
    ...
```

### Hidden content discovery

```
gm> secret

Hidden Resources / Secrets (184 total)
┏━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃Score┃ Type   ┃ Name                   ┃ Reasons              ┃ Details┃
┡━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│  12 │ room   │ room_dw_secret_boss    │ unreachable, special │ boss_… │
│  10 │ object │ obj_secret_door        │ unreachable          │        │
│   9 │ sprite │ spr_ending_epilogue    │ unused               │ 528×…  │
│   8 │ string │ "DebugTeleport"        │ code reference only  │        │
└─────┴───────┴─────────────────────────┴──────────────────────┴───────┘
```

### Graph statistics

```
gm> graph

Graph Statistics:
  Room graph: 252 nodes, 1644 edges, 189 components
  Call graph: 18025 nodes, 11133 edges
  Object graph: 15108 nodes
  Unreachable rooms: 18
```

---

## Architecture

GRET processes a game through several layers:

```
data.win
    │
    ▼
Binary Parser ─── reads all chunks (OBJT, ROOM, CODE, SPRT, …)
    │              outputs typed model objects
    ▼
Intermediate Representation (IR) ─── model objects with resolved numeric IDs
    │
    ▼
Reference Resolver ─── maps every CODE entry to its owner
    │                    builds bidirectional cross-reference indexes
    ▼
Graph Builder ─── constructs three directed graphs:
    │               call graph (code → code),
    │               room graph (room → room),
    │               object graph (room → instance → object → parent → sprite)
    ▼
Query Engine ─── high-level API over resolver + graphs
    │              why, trace, who_uses, search, secret, unreachable
    ▼
Analyzers ─── specialized analysis modules:
    │            dead code, flags, dialogue, transitions, hidden resources
    ▼
CLI / REST API / Browser UI
```

**Binary Parser** (`binary/`): Parses every chunk independently. Each chunk has a dedicated parser (`objt.py`, `sprt.py`, `sond.py`, `room.py`, etc.) that produces typed dataclass model objects. The `DataWinReader` provides direct memory-mapped access to the file.

**Intermediate Representation** (`model/`): All parsed resources are stored as Python dataclasses. Objects, rooms, sprites, sounds, code entries, functions, and variables are plain data with no unresolved IDs.

**Reference Resolver** (`ir/resolver.py`): Classifies each CODE entry by its naming convention (`gml_Object_*`, `gml_Script_*`, `gml_GlobalScript_*`, `gml_Room*`), maps event codes to their owning objects, and builds bidirectional lookup tables across all resource types.

**Graph Builder** (`ir/graph.py`): Produces three `networkx.DiGraph` instances. The call graph encodes every caller→callee relationship. The room graph connects rooms that share object instances. The object graph encodes inheritance, placement, and resource usage.

**Query Engine** (`query/engine.py`): Provides the high-level query API used by the CLI. Commands like `why` and `secret` aggregate information across the resolver, graphs, and analyzers into a single response.

**Analyzers** (`analysis/`, `analyzers/`): Specialized modules for detecting secret content, analyzing dialogue references, and generating reports.

---

## Why GRET?

UndertaleModTool is the standard tool for GameMaker binary editing and decompilation. GRET does not compete with it.

GRET focuses on a different problem: semantic analysis at scale. When you need to understand how hundreds of objects and thousands of code entries relate to each other — who calls whom, which rooms are reachable, what code references a particular sprite, which flags are read but never written — GRET provides answers in seconds.

UTMT answers "what is this?" GRET answers "what does this connect to, who depends on it, and what breaks if it changes?"

The two tools complement each other. Use UTMT for editing and decompilation. Use GRET when you need to map the entire dependency graph of a game and trace the flow of logic across its boundaries.

---

## Roadmap

- [x] Binary parser for all major `data.win` chunks (GMS2.3 format)
- [x] Intermediate representation with typed model objects
- [x] Reference resolver with full cross-reference indexes
- [x] Bytecode decoder with instruction-level analysis
- [x] Call graph generation (deduplicated edges)
- [x] Room graph generation (with shared-object fallback)
- [x] Object graph generation (inheritance, placement, resource usage)
- [x] Hidden content discovery (secret finder)
- [x] Interactive CLI with rich terminal output
- [x] Comprehensive validation suite
- [ ] Version diff engine (compare resources between builds)
- [ ] Secret analyzer 2.0 (pattern-based heuristic scoring)
- [ ] Browser UI (graph-based resource explorer)
- [ ] REST API (HTTP interface for the query engine)
- [ ] Plugin SDK (custom analyzers without core modifications)
- [ ] Graph visualization (export to Graphviz / interactive HTML)

---

## Contributing

Pull requests are welcome. The project is organized into cleanly separated layers — binary parsers, model objects, the resolver, the graph builder, and analyzers — so contributions to any area are straightforward to integrate.

GameMaker reverse engineering knowledge is not required to contribute to most areas. Familiarity with Python static analysis, graph algorithms, or CLI tooling is just as valuable.

If you are working on a particular GameMaker game and discover new chunk formats or event structures, those contributions are especially appreciated.

---

## License

MIT

---

GRET is for researchers, modders, and reverse engineers who want to understand GameMaker games at a structural level. It looks at the whole game, not just individual resources, and asks the questions that editors don't.
