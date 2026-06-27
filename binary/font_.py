from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.font import FontDef, FontGlyph


def parse_font(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, FontDef]:
    fonts: dict[str, FontDef] = {}
    offset = chunk.offset
    count = reader.read_uint32(offset)
    offset += 4

    for font_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        size = reader.read_int32(offset); offset += 4
        bold = reader.read_bool(offset); offset += 1
        italic = reader.read_bool(offset); offset += 1
        charset = reader.read_uint32(offset); offset += 4
        antialias = reader.read_uint32(offset); offset += 4
        range_min = reader.read_uint32(offset); offset += 4
        range_max = reader.read_uint32(offset); offset += 4

        texture_page = reader.read_int32(offset); offset += 4

        font_name = string_table[name_id]
        font = FontDef(id=font_id, name=font_name)
        font.size = size
        font.bold = bold
        font.italic = italic
        font.charset = charset
        font.antialias = antialias
        font.range_min = range_min
        font.range_max = range_max
        font.texture_page = texture_page

        glyph_count = range_max - range_min + 1
        for ch in range(range_min, range_max + 1):
            glyph = FontGlyph(character=ch)
            glyph.x = reader.read_int32(offset); offset += 4
            glyph.y = reader.read_int32(offset); offset += 4
            glyph.w = reader.read_int32(offset); offset += 4
            glyph.h = reader.read_int32(offset); offset += 4
            glyph.shift_x = reader.read_int32(offset); offset += 4
            glyph.shift_y = reader.read_int32(offset); offset += 4
            glyph.texture_page = reader.read_int32(offset); offset += 4
            font.glyphs.append(glyph)

        fonts[font_name] = font

    return fonts
