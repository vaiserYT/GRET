from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.sprite import SpriteDef, SpriteFrame


def parse_sprt(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[int, SpriteDef]:
    sprites: dict[int, SpriteDef] = {}
    offset = chunk.offset
    count = reader.read_uint32(offset)
    offset += 4
    spritemap: dict[int, SpriteDef] = {}

    for sprite_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        width = reader.read_int32(offset); offset += 4
        height = reader.read_int32(offset); offset += 4
        margin_left = reader.read_int32(offset); offset += 4
        margin_right = reader.read_int32(offset); offset += 4
        margin_top = reader.read_int32(offset); offset += 4
        margin_bottom = reader.read_int32(offset); offset += 4

        bbox_left = reader.read_int32(offset); offset += 4
        bbox_right = reader.read_int32(offset); offset += 4
        bbox_top = reader.read_int32(offset); offset += 4
        bbox_bottom = reader.read_int32(offset); offset += 4

        transparent = reader.read_bool(offset); offset += 1
        smooth = reader.read_bool(offset); offset += 1
        preload = reader.read_bool(offset); offset += 1
        offset += 1  # padding

        sprite_name = string_table[name_id]
        sprite = SpriteDef(id=sprite_id, name=sprite_name)
        sprite.width = width
        sprite.height = height
        sprite.margin_left = margin_left
        sprite.margin_right = margin_right
        sprite.margin_top = margin_top
        sprite.margin_bottom = margin_bottom
        sprite.bbox_left = bbox_left
        sprite.bbox_right = bbox_right
        sprite.bbox_top = bbox_top
        sprite.bbox_bottom = bbox_bottom
        sprite.transparent = transparent
        sprite.smooth = smooth
        sprite.preload = preload

        texture_group = reader.read_int32(offset); offset += 4

        frame_count = reader.read_uint32(offset); offset += 4
        sprite.frame_count = frame_count

        has_mask = reader.read_bool(offset); offset += 1
        mask_shape = reader.read_int32(offset); offset += 4
        alpha_tol = reader.read_uint32(offset); offset += 4
        separate_mask = reader.read_bool(offset); offset += 1
        offset += 2  # padding

        origin_x = reader.read_int32(offset); offset += 4
        origin_y = reader.read_int32(offset); offset += 4
        sprite.origin_x = origin_x
        sprite.origin_y = origin_y

        for _ in range(frame_count):
            frame = SpriteFrame()
            frame.texture_page = reader.read_int32(offset); offset += 4
            frame.texture_x = reader.read_int32(offset); offset += 4
            frame.texture_y = reader.read_int32(offset); offset += 4
            frame.texture_w = reader.read_int32(offset); offset += 4
            frame.texture_h = reader.read_int32(offset); offset += 4
            frame.offset_x = reader.read_int32(offset); offset += 4
            frame.offset_y = reader.read_int32(offset); offset += 4
            frame.source_x = reader.read_int32(offset); offset += 4
            frame.source_y = reader.read_int32(offset); offset += 4
            frame.source_w = reader.read_int32(offset); offset += 4
            frame.source_h = reader.read_int32(offset); offset += 4
            sprite.frames.append(frame)

        sprites[sprite_name] = sprite
        spritemap[sprite_id] = sprite

    return sprites
