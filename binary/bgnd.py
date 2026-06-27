from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.background import BackgroundDef


def parse_bgnd(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, BackgroundDef]:
    backgrounds: dict[str, BackgroundDef] = {}
    offset = chunk.offset
    count = reader.read_uint32(offset)
    offset += 4

    for bg_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        transparent = reader.read_bool(offset); offset += 1
        smooth = reader.read_bool(offset); offset += 1
        preload = reader.read_bool(offset); offset += 1
        offset += 1

        texture_page = reader.read_int32(offset); offset += 4
        tex_x = reader.read_int32(offset); offset += 4
        tex_y = reader.read_int32(offset); offset += 4
        tex_w = reader.read_int32(offset); offset += 4
        tex_h = reader.read_int32(offset); offset += 4
        src_x = reader.read_int32(offset); offset += 4
        src_y = reader.read_int32(offset); offset += 4
        src_w = reader.read_int32(offset); offset += 4
        src_h = reader.read_int32(offset); offset += 4

        tile_h = reader.read_bool(offset); offset += 1
        tile_v = reader.read_bool(offset); offset += 1
        offset += 2
        hspeed = reader.read_int32(offset); offset += 4
        vspeed = reader.read_int32(offset); offset += 4
        width = reader.read_int32(offset); offset += 4
        height = reader.read_int32(offset); offset += 4

        bg_name = string_table[name_id]
        bg = BackgroundDef(id=bg_id, name=bg_name)
        bg.width = width
        bg.height = height
        bg.transparent = transparent
        bg.smooth = smooth
        bg.preload = preload
        bg.texture_page = texture_page
        bg.texture_x = tex_x
        bg.texture_y = tex_y
        bg.texture_w = tex_w
        bg.texture_h = tex_h
        bg.source_x = src_x
        bg.source_y = src_y
        bg.source_w = src_w
        bg.source_h = src_h
        bg.tile_h = tile_h
        bg.tile_v = tile_v
        bg.hspeed = hspeed
        bg.vspeed = vspeed

        backgrounds[bg_name] = bg

    return backgrounds
