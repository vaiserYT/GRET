from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from binary.reader import DataWinReader, locate_chunks
from binary.strg import StringTable
from binary.gms2_parsers import (
    parse_objects_gms2,
    parse_sprites_gms2,
    parse_sounds_gms2,
    parse_rooms_gms2,
    parse_code_gms2,
    parse_functions_gms2,
    parse_variables_gms2,
)
from code.decoder import decode_instructions
from code.opcodes import Opcode, is_call
from model.game import Game
from ir.resolver import Resolver
from ir.graph import ResourceGraph


def load_game(path: str | Path, show_progress: bool = True) -> Game:
    reader = DataWinReader(Path(path))
    chunks = locate_chunks(reader)
    game = Game()
    game.path = Path(path)

    progress_cols = [
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    ]

    ctx = (
        Progress(*progress_cols, console=Console(stderr=True))
        if show_progress
        else Progress(disable=True)
    )

    with ctx as progress:
        main_task = progress.add_task("[cyan]Loading data.win...", total=10)

        # STRG
        if "STRG" in chunks:
            progress.update(main_task, description="[cyan]Reading strings...")
            st = StringTable()
            st.parse(reader, chunks["STRG"])
            game.strings = st
            reader.string_table = st
        progress.advance(main_task)

        # SPRT
        if "SPRT" in chunks:
            progress.update(main_task, description="[cyan]Parsing sprites...")
            game.sprites = parse_sprites_gms2(reader, chunks["SPRT"], game.strings)
        progress.advance(main_task)

        # SOND
        if "SOND" in chunks:
            progress.update(main_task, description="[cyan]Parsing sounds...")
            game.sounds = parse_sounds_gms2(reader, chunks["SOND"], game.strings)
        progress.advance(main_task)

        # OBJT
        if "OBJT" in chunks:
            progress.update(main_task, description="[cyan]Parsing objects...")
            game.objects = parse_objects_gms2(reader, chunks["OBJT"], game.strings)
        progress.advance(main_task)

        # ROOM
        if "ROOM" in chunks:
            progress.update(main_task, description="[cyan]Parsing rooms...")
            game.rooms = parse_rooms_gms2(reader, chunks["ROOM"], game.strings)
        progress.advance(main_task)

        # FUNC
        if "FUNC" in chunks:
            progress.update(main_task, description="[cyan]Parsing functions...")
            game.functions = parse_functions_gms2(reader, chunks["FUNC"], game.strings)
            # Build func_names and func_code_offsets arrays from raw FUNC table
            func_count = reader.read_uint32(chunks["FUNC"].offset)
            game.func_names = [""] * func_count
            game.func_code_offsets = [0] * func_count
            for i in range(func_count):
                off = chunks["FUNC"].offset + 4 + i * 12
                if off + 12 > reader.size:
                    break
                name_id = reader.read_int32(off + 4)
                code_off = reader.read_uint32(off + 8)
                game.func_code_offsets[i] = code_off
                if 0 <= name_id < len(game.strings):
                    game.func_names[i] = game.strings[name_id]
        progress.advance(main_task)

        # VARI
        if "VARI" in chunks:
            progress.update(main_task, description="[cyan]Parsing variables...")
            game.variables = parse_variables_gms2(reader, chunks["VARI"], game.strings)
        progress.advance(main_task)

        # Build lookup maps needed by the code decoder
        function_map: dict[str, int] = {
            name: func.id for name, func in game.functions.items()
        }
        variable_map: dict[str, int] = {
            var.name: var_id for var_id, var in game.variables.items()
        }

        # CODE — slowest step, with its own sub-progress
        if "CODE" in chunks:
            progress.update(main_task, description="[cyan]Decoding bytecode...")
            reader._chunk_strg = chunks.get("STRG")
            code_entries = parse_code_gms2(reader, chunks["CODE"], game.strings)
            game.code_offsets = {cid: e.offset for cid, e in code_entries.items()}

            if show_progress:
                code_task = progress.add_task(
                    "[bright_black]  instructions...", total=len(code_entries)
                )
            for code_id, entry in code_entries.items():
                if entry.length <= 0 or entry.length > 1024 * 1024:
                    continue
                try:
                    instructions = decode_instructions(
                        reader, entry.offset, entry.length,
                        game.strings, function_map, variable_map,
                    )
                    entry.instructions = instructions
                    for instr in instructions:
                        if is_call(instr.opcode) and instr.value_func_id >= 0:
                            call_type = instr.instruction_type
                            entry.calls.append((instr.value_func_id, instr.value_arg_count, call_type))
                        if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                            entry.string_refs.append(instr.value_str_id)
                        if instr.opcode == Opcode.PUSHBLTN and instr.value_variable_id >= 0:
                            entry.variable_refs.append((instr.value_variable_id, 0))
                    game.code_entries[code_id] = entry
                except Exception:
                    pass
                if show_progress:
                    progress.advance(code_task)
            if show_progress:
                progress.remove_task(code_task)
        progress.advance(main_task)

        reader.close()

        # Resolver
        progress.update(main_task, description="[cyan]Building resolver...")
        res = Resolver()
        res.build(game)
        game.resolver = res
        progress.advance(main_task)

        # Graph
        progress.update(main_task, description="[cyan]Building graph...")
        rgraph = ResourceGraph(game, res)
        rgraph.build_all()
        game.rgraph = rgraph
        progress.advance(main_task)

    return game
