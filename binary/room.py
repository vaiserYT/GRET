from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.room_ import RoomDef, RoomInstance, RoomBackground, RoomView, RoomLayer


def _read_name(reader: DataWinReader, name_ref: int) -> str:
    """Read a resource name at a file offset (C string in STRG data area)."""
    if name_ref > 0 and name_ref < reader.size:
        try:
            return reader.read_cstring(name_ref)
        except Exception:
            pass
    return ""


def parse_room_gms1(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, RoomDef]:
    """Legacy GMS 1.x / early GMS2 sequential room parser.
    
    Kept for reference comparison against the GMS2.3 parser.
    """
    rooms: dict[str, RoomDef] = {}
    offset = chunk.offset

    count = reader.read_uint32(offset)
    offset += 4

    for room_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        caption_id = reader.read_uint32(offset); offset += 4
        width = reader.read_int32(offset); offset += 4
        height = reader.read_int32(offset); offset += 4
        speed = reader.read_uint32(offset); offset += 4
        persistent = reader.read_bool(offset); offset += 1
        offset += 3

        colour = reader.read_uint32(offset); offset += 4
        show_colour = reader.read_bool(offset); offset += 1
        offset += 3

        creation_code_id = reader.read_int32(offset); offset += 4

        room_name = string_table[name_id]
        room_caption = string_table[caption_id] if caption_id >= 0 else ""
        room = RoomDef(
            id=room_id,
            name=room_name,
            caption=room_caption,
            width=width,
            height=height,
            speed=speed,
            persistent=persistent,
            colour=colour,
            creation_code_id=creation_code_id,
        )

        bg_count = reader.read_uint32(offset)
        offset += 4
        for _ in range(bg_count):
            bg = RoomBackground()
            bg.enabled = reader.read_bool(offset); offset += 1
            bg.visible = reader.read_bool(offset); offset += 1
            bg.foreground = reader.read_bool(offset); offset += 1
            offset += 1
            bg.background_id = reader.read_int32(offset); offset += 4
            bg.x = reader.read_int32(offset); offset += 4
            bg.y = reader.read_int32(offset); offset += 4
            bg.tile_x = reader.read_bool(offset); offset += 1
            bg.tile_y = reader.read_bool(offset); offset += 1
            offset += 2
            bg.hspeed = reader.read_int32(offset); offset += 4
            bg.vspeed = reader.read_int32(offset); offset += 4
            bg.alpha = reader.read_float(offset); offset += 4
            room.backgrounds.append(bg)

        view_count = reader.read_uint32(offset)
        offset += 4
        for _ in range(view_count):
            view = RoomView()
            view.enabled = reader.read_bool(offset); offset += 1
            offset += 3
            view.x = reader.read_int32(offset); offset += 4
            view.y = reader.read_int32(offset); offset += 4
            view.w = reader.read_int32(offset); offset += 4
            view.h = reader.read_int32(offset); offset += 4
            view.port_x = reader.read_int32(offset); offset += 4
            view.port_y = reader.read_int32(offset); offset += 4
            view.port_w = reader.read_int32(offset); offset += 4
            view.port_h = reader.read_int32(offset); offset += 4
            view.border_x = reader.read_int32(offset); offset += 4
            view.border_y = reader.read_int32(offset); offset += 4
            view.speed = reader.read_int32(offset); offset += 4
            view.follow_object_id = reader.read_int32(offset); offset += 4
            room.views.append(view)

        game_object_id = reader.read_int32(offset); offset += 4

        inst_count = reader.read_uint32(offset)
        offset += 4
        for _ in range(inst_count):
            inst = RoomInstance(object_id=0, x=0, y=0)
            inst.object_id = reader.read_int32(offset); offset += 4
            inst.x = reader.read_int32(offset); offset += 4
            inst.y = reader.read_int32(offset); offset += 4
            inst.instance_id = reader.read_int32(offset); offset += 4
            inst.creation_code_id = reader.read_int32(offset); offset += 4
            inst.scale_x = reader.read_float(offset); offset += 4
            inst.scale_y = reader.read_float(offset); offset += 4
            inst.rotation = reader.read_float(offset); offset += 4
            inst.colour = reader.read_int32(offset); offset += 4
            inst.alpha = reader.read_float(offset); offset += 4
            inst.layer_depth = reader.read_int32(offset); offset += 4
            inst.image_index = reader.read_float(offset); offset += 4
            inst.image_speed = reader.read_float(offset); offset += 4
            inst.persistent = reader.read_bool(offset); offset += 1
            offset += 11
            room.instances.append(inst)

        rooms[room_name] = room

    return rooms


def parse_room_gms2_3(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[int, RoomDef]:
    """GMS2.3 room parser matching the implementation in gms2_parsers.py.
    
    Uses section pointers and layer data instead of sequential format.
    """
    rooms: dict[int, RoomDef] = {}
    offset = chunk.offset

    count = reader.read_uint32(offset)
    offset += 4

    offsets: list[int] = []
    for i in range(count):
        off = reader.read_uint32(offset)
        offsets.append(off)
        offset += 4

    for room_id, entry_off in enumerate(offsets):
        if entry_off <= 0 or entry_off + 96 > reader.size:
            continue

        name_str = _read_name(reader, reader.read_int32(entry_off + 0))
        if not name_str:
            name_str = f"<room_{room_id}>"

        room = RoomDef(id=room_id, name=name_str)
        room.caption = _read_name(reader, reader.read_int32(entry_off + 4))
        room.width = reader.read_uint32(entry_off + 8)
        room.height = reader.read_uint32(entry_off + 12)
        room.speed = reader.read_uint32(entry_off + 16)
        room.persistent = reader.read_bool(entry_off + 20)
        room.colour = reader.read_uint32(entry_off + 24)
        room.creation_code_id = reader.read_int32(entry_off + 32)
        room.flags = reader.read_uint32(entry_off + 36)

        bg_ptr = reader.read_uint32(entry_off + 40)
        view_ptr = reader.read_uint32(entry_off + 44)
        obj_ptr = reader.read_uint32(entry_off + 48)
        tile_ptr = reader.read_uint32(entry_off + 52)

        room.physics_top = reader.read_uint32(entry_off + 60)
        room.physics_left = reader.read_uint32(entry_off + 64)
        room.physics_right = reader.read_uint32(entry_off + 68)
        room.physics_bottom = reader.read_uint32(entry_off + 72)
        room.physics_gravity_x = reader.read_float(entry_off + 76)
        room.physics_gravity_y = reader.read_float(entry_off + 80)
        room.meters_per_pixel = reader.read_float(entry_off + 84)

        layers_ptr = reader.read_uint32(entry_off + 88)
        sequences_ptr = reader.read_uint32(entry_off + 92)

        room_end = offsets[room_id + 1] if room_id + 1 < len(offsets) else min(chunk.offset + chunk.size, reader.size)

        def _read_ptr_list(base_ptr, max_items=100000):
            if base_ptr <= 0 or base_ptr >= reader.size:
                return []
            count = reader.read_uint32(base_ptr)
            if count > max_items:
                return []
            ptrs = []
            for i in range(count):
                p = reader.read_uint32(base_ptr + 4 + i * 4)
                if 0 < p < reader.size:
                    ptrs.append(p)
            return ptrs

        # -- Backgrounds (40-byte entries at each pointer) --
        for bg_data_off in _read_ptr_list(bg_ptr, 100):
            if bg_data_off + 40 > room_end:
                break
            tile_x = reader.read_int32(bg_data_off + 16)
            tile_y = reader.read_int32(bg_data_off + 20)
            bg = RoomBackground(
                enabled=reader.read_bool(bg_data_off),
                foreground=reader.read_bool(bg_data_off + 1),
                background_id=reader.read_int32(bg_data_off + 4),
                x=reader.read_int32(bg_data_off + 8),
                y=reader.read_int32(bg_data_off + 12),
                tile_x=tile_x != 0,
                tile_y=tile_y != 0,
                hspeed=reader.read_int32(bg_data_off + 24),
                vspeed=reader.read_int32(bg_data_off + 28),
            )
            bg.stretch = reader.read_bool(bg_data_off + 32)
            room.backgrounds.append(bg)

        # -- Views (56-byte entries at each pointer) --
        for view_data_off in _read_ptr_list(view_ptr, 32):
            if view_data_off + 56 > room_end:
                break
            view = RoomView(
                enabled=reader.read_bool(view_data_off),
                x=reader.read_int32(view_data_off + 4),
                y=reader.read_int32(view_data_off + 8),
                w=reader.read_int32(view_data_off + 12),
                h=reader.read_int32(view_data_off + 16),
                port_x=reader.read_int32(view_data_off + 20),
                port_y=reader.read_int32(view_data_off + 24),
                port_w=reader.read_int32(view_data_off + 28),
                port_h=reader.read_int32(view_data_off + 32),
                border_x=reader.read_int32(view_data_off + 36),
                border_y=reader.read_int32(view_data_off + 40),
                speed=reader.read_int32(view_data_off + 44),
                follow_object_id=reader.read_int32(view_data_off + 48),
            )
            room.views.append(view)

        # -- Game Objects (48-byte entries at each pointer) --
        game_objects: dict[int, dict] = {}
        for go_data_off in _read_ptr_list(obj_ptr, 100000):
            if go_data_off + 48 > room_end:
                break
            inst_id = reader.read_uint32(go_data_off + 12)
            game_objects[inst_id] = {
                "object_id": reader.read_int32(go_data_off + 8),
                "x": reader.read_int32(go_data_off),
                "y": reader.read_int32(go_data_off + 4),
                "creation_code_id": reader.read_int32(go_data_off + 16),
                "scale_x": reader.read_float(go_data_off + 20),
                "scale_y": reader.read_float(go_data_off + 24),
                "image_speed": reader.read_float(go_data_off + 28),
                "image_index": reader.read_int32(go_data_off + 32),
                "colour": reader.read_uint32(go_data_off + 36),
                "rotation": reader.read_float(go_data_off + 40),
                "pre_cc_id": reader.read_int32(go_data_off + 44),
            }

        # -- Layers (GMS2+) --
        for layer_data_off in _read_ptr_list(layers_ptr, 1000):
            if layer_data_off + 36 > room_end:
                break
            layer_name_str = _read_name(reader, reader.read_int32(layer_data_off))
            layer_type = reader.read_uint32(layer_data_off + 8)
            layer_depth = reader.read_int32(layer_data_off + 12)

            layer = RoomLayer(
                name=layer_name_str,
                depth=layer_depth,
                visible=reader.read_bool(layer_data_off + 32),
                layer_type=layer_type,
            )
            room.layers.append(layer)

            # Layer-specific data starts after 36-byte header
            # Then a 12-byte common header: sub_type(4) + always_0(4) + always_0(4)
            data_off = layer_data_off + 36 + 12
            if layer_type == 2:  # Instances
                if data_off + 4 <= min(room_end, reader.size):
                    inst_count2 = reader.read_uint32(data_off)
                    if inst_count2 <= 100000:
                        ioff = data_off + 4
                        for _ in range(inst_count2):
                            if ioff + 4 > room_end:
                                break
                            iid = reader.read_uint32(ioff)
                            if iid in game_objects:
                                go = game_objects[iid]
                                inst = RoomInstance(
                                    object_id=go["object_id"],
                                    x=go["x"],
                                    y=go["y"],
                                    instance_id=iid,
                                    creation_code_id=go["creation_code_id"],
                                    scale_x=go["scale_x"],
                                    scale_y=go["scale_y"],
                                    rotation=go["rotation"],
                                    colour=go["colour"],
                                    alpha=1.0,
                                    layer_depth=layer_depth,
                                    image_index=float(go["image_index"]),
                                    image_speed=go["image_speed"],
                                )
                                room.instances.append(inst)
                            ioff += 4

        rooms[room_id] = room

    return rooms
