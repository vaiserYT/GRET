from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.object_ import ObjectDef, EventDef


def parse_objt(reader: DataWinReader, chunk: ChunkInfo, string_table, dafl_objects: dict[str, ObjectDef]) -> None:
    offset = chunk.offset

    obj_count = reader.read_uint32(offset)
    offset += 4

    for obj_id in range(obj_count):
        name_id = reader.read_uint32(offset); offset += 4
        sprite_id = reader.read_int32(offset); offset += 4
        mask_id = reader.read_int32(offset); offset += 4
        parent_id = reader.read_int32(offset); offset += 4

        solid = reader.read_bool(offset); offset += 1
        persistent = reader.read_bool(offset); offset += 1
        offset += 2

        depth = reader.read_int32(offset); offset += 4

        obj_name = string_table[name_id]
        obj = dafl_objects.get(obj_name)
        if obj is None:
            if obj_name not in dafl_objects:
                obj = ObjectDef(id=obj_id, name=obj_name)
                dafl_objects[obj_name] = obj
            else:
                obj = dafl_objects[obj_name]

        if obj.sprite_index < 0:
            obj.sprite_index = sprite_id
        if obj.mask_index < 0:
            obj.mask_index = mask_id
        if obj.parent_index < 0:
            obj.parent_index = parent_id
        obj.solid = solid
        obj.persistent = persistent
        obj.depth = depth

        event_count = reader.read_uint32(offset)
        offset += 4

        for _ in range(event_count):
            event_type = reader.read_int32(offset); offset += 4
            event_subtype = reader.read_int32(offset); offset += 4
            code_id = reader.read_int32(offset); offset += 4
            code_length = reader.read_int32(offset); offset += 4

            if not obj.has_event(event_type, event_subtype):
                ev = EventDef(
                    event_type=event_type,
                    subtype=event_subtype,
                    code_id=code_id,
                    code_length=code_length,
                )
                obj.events.append(ev)
