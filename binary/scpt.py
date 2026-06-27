from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.script import ScriptDef


def parse_scpt(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, ScriptDef]:
    scripts: dict[str, ScriptDef] = {}
    offset = chunk.offset

    count = reader.read_uint32(offset)
    offset += 4

    for scr_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        code_id = reader.read_int32(offset); offset += 4
        code_offset = reader.read_int32(offset); offset += 4
        code_length = reader.read_int32(offset); offset += 4

        scr_name = string_table[name_id]
        script = ScriptDef(
            id=scr_id,
            name=scr_name,
            code_id=code_id,
            code_offset=code_offset,
            code_length=code_length,
        )
        scripts[scr_name] = script

    return scripts


def parse_glob(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, ScriptDef]:
    scripts: dict[str, ScriptDef] = {}
    offset = chunk.offset

    count = reader.read_uint32(offset)
    offset += 4

    for scr_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        code_id = reader.read_int32(offset); offset += 4
        code_offset = reader.read_int32(offset); offset += 4
        code_length = reader.read_int32(offset); offset += 4

        scr_name = string_table[name_id]
        script = ScriptDef(
            id=scr_id,
            name=scr_name,
            code_id=code_id,
            code_offset=code_offset,
            code_length=code_length,
            is_global=True,
        )
        scripts[scr_name] = script

    return scripts
