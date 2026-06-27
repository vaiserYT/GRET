from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.object_ import ObjectDef, EventDef, ActionDef
from model.room_ import RoomDef, RoomInstance, RoomBackground, RoomView, RoomLayer
from model.sprite import SpriteDef, SpriteFrame
from model.sound import SoundDef
from model.function import FunctionDef, FunctionArg
from model.variable import VariableDef, VariableKind


def _read_index_table(reader: DataWinReader, chunk: ChunkInfo) -> list[int]:
    offsets: list[int] = []
    offset = chunk.offset
    if offset + 4 > reader.size:
        return offsets
    count = reader.read_uint32(offset)
    if count > 100000:
        return offsets
    offset += 4

    table_end = chunk.offset + chunk.size
    for _ in range(count):
        if offset + 4 > table_end or offset + 4 > reader.size:
            break
        file_off = reader.read_uint32(offset)
        offsets.append(file_off)
        offset += 4

    return offsets


def _read_name(reader: DataWinReader, name_ref: int) -> str:
    """Read a resource name at a file offset (C string in STRG data area)."""
    if name_ref > 0 and name_ref < reader.size:
        try:
            return reader.read_cstring(name_ref)
        except Exception:
            pass
    return ""


def parse_objects_gms2(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[int, ObjectDef]:
    objects: dict[int, ObjectDef] = {}
    offsets = _read_index_table(reader, chunk)

    # Read CODE chunk info for validating code_id references
    code_chunk_off = 0
    code_count = 0
    for ch in getattr(reader, '_chunks', []):
        if hasattr(ch, 'name') and ch.name == "CODE":
            code_chunk_off = ch.offset
            code_count = reader.read_uint32(code_chunk_off) if code_chunk_off + 4 <= reader.size else 0
            break

    objt_size = chunk.offset + chunk.size if hasattr(chunk, 'size') else reader.size

    for obj_id, entry_off in enumerate(offsets):
        if entry_off <= 0 or entry_off + 68 > reader.size:
            continue

        # [+0] = name_ptr (file offset to C string in STRG)
        name_str = _read_name(reader, reader.read_int32(entry_off + 0))
        if not name_str:
            name_str = f"<obj_{obj_id}>"

        # GMS2.3 OBJT header: 68 bytes (16 fields × 4 bytes each, bools as int32)
        # [+4] sprite_id, [+8] visible, [+12] managed (>=2022.5), [+16] solid,
        # [+20] depth, [+24] persistent, [+28] parent_id, [+32] texture_mask_id,
        # [+36] uses_physics, [+40] is_sensor, [+44] collision_shape,
        # [+48] density, [+52] restitution, [+56] group, [+60] linear_damping,
        # [+64] angular_damping
        obj = ObjectDef(
            id=obj_id,
            name=name_str,
            sprite_index=reader.read_int32(entry_off + 4),
            mask_index=reader.read_int32(entry_off + 32),
            parent_index=reader.read_int32(entry_off + 28),
            solid=reader.read_int32(entry_off + 16) != 0,
            persistent=reader.read_int32(entry_off + 24) != 0,
            visible=reader.read_int32(entry_off + 8) != 0,
            depth=reader.read_int32(entry_off + 20),
        )
        obj.physics = reader.read_int32(entry_off + 36) != 0

        # Physics vertex data follows the 68-byte header:
        # [+68] vertex_count (int32), [+72] friction (float), [+76] awake (byte),
        # [+77] kinematic (byte), [+78..+83] padding (6 bytes),
        # [+84] vertices (vertex_count × 8 bytes: float x, float y each)
        vertex_count = reader.read_int32(entry_off + 68) if entry_off + 72 <= reader.size else 0
        events_start = entry_off + 84 + vertex_count * 8

        # Events: two-level UndertalePointerList
        # 15 event type slots (0-14), each slot has count + count*pointers
        # Each event: [+0] subtype (uint32), [+4] actions_count (uint32),
        #   [+8..] actions_count × pointers to ActionDef
        # Each action: 56-byte structure with code_id at [+32]
        if events_start + 4 <= reader.size:
            ev_type_count = reader.read_uint32(events_start)
            if 0 < ev_type_count <= 16:
                type_ptr_off = events_start + 4
                for ti in range(ev_type_count):
                    if type_ptr_off + 4 > reader.size:
                        break
                    subtype_list_ptr = reader.read_uint32(type_ptr_off)
                    type_ptr_off += 4

                    if subtype_list_ptr == 0:
                        continue
                    if subtype_list_ptr + 4 > reader.size:
                        continue

                    sc = reader.read_uint32(subtype_list_ptr)
                    if sc == 0 or sc > 100:
                        continue

                    ev_ptr_off = subtype_list_ptr + 4
                    for si in range(sc):
                        if ev_ptr_off + 4 > reader.size:
                            break
                        ev_ptr = reader.read_uint32(ev_ptr_off)
                        ev_ptr_off += 4

                        if ev_ptr == 0 or ev_ptr + 8 > reader.size:
                            continue

                        ev_subtype = reader.read_uint32(ev_ptr)
                        act_count = reader.read_uint32(ev_ptr + 4)
                        if act_count == 0 or act_count > 100:
                            continue

                        ev = EventDef(event_type=ti, subtype=ev_subtype)

                        act_ptr_off = ev_ptr + 8
                        for ai in range(act_count):
                            if act_ptr_off + 4 > reader.size:
                                break
                            act_ptr = reader.read_uint32(act_ptr_off)
                            act_ptr_off += 4

                            if act_ptr == 0 or act_ptr + 56 > reader.size:
                                continue

                            # 56-byte action structure
                            lib_id = reader.read_int32(act_ptr)
                            id_val = reader.read_int32(act_ptr + 4)
                            kind = reader.read_int32(act_ptr + 8)
                            use_rel = reader.read_bool(act_ptr + 12)
                            is_quest = reader.read_bool(act_ptr + 13)
                            use_apply = reader.read_bool(act_ptr + 14)
                            exe_type = reader.read_int32(act_ptr + 16)
                            action_name = reader.read_int32(act_ptr + 20)
                            args_count = reader.read_int32(act_ptr + 24)
                            # [+28] = arg1 (0 or 1 for PreCreate)
                            code_id = reader.read_int32(act_ptr + 32)
                            who = reader.read_int32(act_ptr + 36)
                            relative = reader.read_bool(act_ptr + 44)
                            is_not = reader.read_bool(act_ptr + 45)

                            act = ActionDef(
                                lib_id=lib_id,
                                id=id_val,
                                kind=kind,
                                use_relative=use_rel,
                                is_question=is_quest,
                                use_apply_to=use_apply,
                                exe_type=exe_type,
                                action_name=action_name,
                                args_count=args_count,
                                code_id=code_id,
                                who=who,
                                relative=relative,
                                is_not=is_not,
                            )
                            ev.actions.append(act)

                            # Set event-level code_id from first action
                            if ev.code_id < 0 and code_id >= 0:
                                ev.code_id = code_id

                        obj.events.append(ev)

        objects[obj_id] = obj

    return objects


def parse_sprites_gms2(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[int, SpriteDef]:
    sprites: dict[int, SpriteDef] = {}
    offsets = _read_index_table(reader, chunk)

    for spr_id, entry_off in enumerate(offsets):
        if entry_off <= 0 or entry_off + 80 > reader.size:
            continue
        name_str = _read_name(reader, reader.read_int32(entry_off + 0))
        if not name_str:
            name_str = f"<spr_{spr_id}>"

        sprite = SpriteDef(id=spr_id, name=name_str)
        sprite.width = reader.read_int32(entry_off + 4)
        sprite.height = reader.read_int32(entry_off + 8)
        sprite.margin_left = reader.read_int32(entry_off + 12)
        sprite.margin_right = reader.read_int32(entry_off + 16)
        sprite.margin_top = reader.read_int32(entry_off + 20)
        sprite.margin_bottom = reader.read_int32(entry_off + 24)
        sprite.bbox_left = reader.read_int32(entry_off + 28)
        sprite.bbox_right = reader.read_int32(entry_off + 32)
        sprite.bbox_top = reader.read_int32(entry_off + 36)
        sprite.bbox_bottom = reader.read_int32(entry_off + 40)
        sprite.transparent = reader.read_bool(entry_off + 44)
        sprite.smooth = reader.read_bool(entry_off + 45)
        sprite.preload = reader.read_bool(entry_off + 46)

        frame_count = reader.read_int32(entry_off + 48)
        if frame_count < 0 or frame_count > 500:
            frame_count = 0
        sprite.frame_count = frame_count

        sprite.texture_group = reader.read_int32(entry_off + 52)
        sprite.origin_x = reader.read_int32(entry_off + 56)
        sprite.origin_y = reader.read_int32(entry_off + 60)

        frame_off = entry_off + 64
        for f in range(sprite.frame_count):
            if frame_off + 48 > reader.size:
                break
            frame = SpriteFrame(
                texture_page=reader.read_int32(frame_off),
                texture_x=reader.read_int32(frame_off + 4),
                texture_y=reader.read_int32(frame_off + 8),
                texture_w=reader.read_int32(frame_off + 12),
                texture_h=reader.read_int32(frame_off + 16),
                offset_x=reader.read_int32(frame_off + 20),
                offset_y=reader.read_int32(frame_off + 24),
                source_x=reader.read_int32(frame_off + 28),
                source_y=reader.read_int32(frame_off + 32),
                source_w=reader.read_int32(frame_off + 36),
                source_h=reader.read_int32(frame_off + 40),
            )
            sprite.frames.append(frame)
            frame_off += 44

        sprites[spr_id] = sprite

    return sprites


def parse_sounds_gms2(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[int, SoundDef]:
    sounds: dict[int, SoundDef] = {}
    offsets = _read_index_table(reader, chunk)

    for snd_id, entry_off in enumerate(offsets):
        if entry_off <= 0 or entry_off + 40 > reader.size:
            continue
        name_str = _read_name(reader, reader.read_int32(entry_off + 0))
        if not name_str:
            name_str = f"<snd_{snd_id}>"
        file_id = reader.read_int32(entry_off + 12)
        sound = SoundDef(
            id=snd_id,
            name=name_str,
            type=reader.read_int32(entry_off + 4),
            file=string_table[file_id] if 0 <= file_id < len(string_table) else "",
            volume=reader.read_float(entry_off + 8),
            pitch=reader.read_float(entry_off + 12),
            preload=reader.read_bool(entry_off + 16),
            audio_group=reader.read_int32(entry_off + 20),
            data_offset=reader.read_int32(entry_off + 24),
            data_size=reader.read_int32(entry_off + 28),
        )
        sounds[snd_id] = sound

    return sounds


def parse_rooms_gms2(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[int, RoomDef]:
    rooms: dict[int, RoomDef] = {}
    offsets = _read_index_table(reader, chunk)

    for room_id, entry_off in enumerate(offsets):
        if entry_off <= 0 or entry_off + 96 > reader.size:
            continue

        # GMS2.3 room header: [+0]=name_ptr [+4]=caption_ptr [+8]=width [+12]=height
        # [+16]=speed [+20]=persistent [+24]=bg_color [+28]=unknown [+32]=cc_id [+36]=flags
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

        # Section pointers
        bg_ptr = reader.read_uint32(entry_off + 40)
        view_ptr = reader.read_uint32(entry_off + 44)
        obj_ptr = reader.read_uint32(entry_off + 48)
        tile_ptr = reader.read_uint32(entry_off + 52)

        # Misc fields
        room.physics_top = reader.read_uint32(entry_off + 60)
        room.physics_left = reader.read_uint32(entry_off + 64)
        room.physics_right = reader.read_uint32(entry_off + 68)
        room.physics_bottom = reader.read_uint32(entry_off + 72)
        room.physics_gravity_x = reader.read_float(entry_off + 76)
        room.physics_gravity_y = reader.read_float(entry_off + 80)
        room.meters_per_pixel = reader.read_float(entry_off + 84)

        # GMS2+ pointers
        layers_ptr = reader.read_uint32(entry_off + 88)
        sequences_ptr = reader.read_uint32(entry_off + 92)

        # Parse section data by following pointers
        room_end = offsets[room_id + 1] if room_id + 1 < len(offsets) else min(chunk.offset + chunk.size, reader.size)

        # Helper: read count + count*pointers, return list of data offsets
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


def parse_code_gms2(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[int, CodeEntry]:
    from model.code_ import CodeEntry

    entries: dict[int, CodeEntry] = {}
    offsets = _read_index_table(reader, chunk)

    for code_id, entry_off in enumerate(offsets):
        if entry_off <= 0 or entry_off + 20 > reader.size:
            continue

        name_str_off = reader.read_uint32(entry_off)           # [+0] file offset to name in STRG
        bytecode_length = reader.read_uint32(entry_off + 4)     # [+4] bytecode length
        locals_and_args = reader.read_uint32(entry_off + 8)     # [+8] locals | args
        rel_addr_signed = reader.read_int32(entry_off + 12)     # [+12] relative address (int32)
        blob_offset = reader.read_uint32(entry_off + 16)        # [+16] offset within blob

        locals_count = locals_and_args & 0xFFFF
        args_and_flag = (locals_and_args >> 16) & 0xFFFF
        args_count = args_and_flag & 0x7FFF

        # Parse function name from STRG data area
        name_str = ""
        strg_info = None
        if hasattr(reader, 'string_table') and reader.string_table:
            strg_info = getattr(reader, '_chunk_strg', None)
        if strg_info is not None and strg_info.offset <= name_str_off < strg_info.offset + strg_info.size:
            name_str = reader.read_cstring(name_str_off)

        # Compute absolute bytecode address
        bytecode_abs = entry_off + 20 + rel_addr_signed

        entry = CodeEntry(
            id=code_id,
            offset=bytecode_abs + blob_offset,
            length=bytecode_length - blob_offset if blob_offset > 0 else bytecode_length,
            name=name_str,
            name_str_off=name_str_off,
            entry_off=entry_off,
            bytecode_rel_addr=rel_addr_signed,
            bytecode_offset_within_blob=blob_offset,
            locals_count=locals_count,
            arguments_count=args_count,
        )
        entries[code_id] = entry

    return entries


def parse_functions_gms2(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, FunctionDef]:
    functions: dict[str, FunctionDef] = {}
    count = reader.read_uint32(chunk.offset)
    if count > 100000:
        return functions
    for func_id in range(count):
        off = chunk.offset + 4 + func_id * 12
        if off + 12 > chunk.offset + chunk.size:
            break
        name_or_id = reader.read_int32(off + 4)
        code_off = reader.read_uint32(off + 8)
        name_str = string_table[name_or_id] if 0 <= name_or_id < len(string_table) else f"<func_{func_id}>"
        if name_str:
            func = FunctionDef(id=func_id, name=name_str, code_offset=code_off)
            functions[name_str] = func
    return functions


def parse_variables_gms2(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[int, VariableDef]:
    variables: dict[int, VariableDef] = {}
    offsets = _read_index_table(reader, chunk)

    for var_id, entry_off in enumerate(offsets):
        if entry_off <= 0 or entry_off + 16 > reader.size:
            continue
        name_id = reader.read_int32(entry_off + 4)
        name_str = string_table[name_id] if 0 <= name_id < len(string_table) else f"<var_{var_id}>"
        var_kind_int = reader.read_int32(entry_off + 8)
        is_array = reader.read_bool(entry_off + 12)
        init_val_id = reader.read_int32(entry_off + 16)
        try:
            kind = VariableKind(var_kind_int) if var_kind_int >= 0 else VariableKind.GLOBAL
        except ValueError:
            kind = VariableKind.GLOBAL
        var = VariableDef(
            id=var_id,
            name=name_str,
            kind=kind,
            is_array=is_array,
            init_value=string_table[init_val_id] if 0 <= init_val_id < len(string_table) else "",
        )
        variables[var_id] = var

    return variables
