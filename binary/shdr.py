from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.shader import ShaderDef


def parse_shdr(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, ShaderDef]:
    shaders: dict[str, ShaderDef] = {}
    offset = chunk.offset
    count = reader.read_uint32(offset)
    offset += 4

    for sh_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        sh_type = reader.read_int32(offset); offset += 4

        sh_name = string_table[name_id]
        shader = ShaderDef(id=sh_id, name=sh_name, type=sh_type)

        vertex_id = reader.read_int32(offset); offset += 4
        fragment_id = reader.read_int32(offset); offset += 4

        if vertex_id >= 0:
            shader.vertex_source = string_table[vertex_id]
        if fragment_id >= 0:
            shader.fragment_source = string_table[fragment_id]

        shaders[sh_name] = shader

    return shaders
