from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.timeline import TimelineDef, TimelineMoment


def parse_tmln(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, TimelineDef]:
    timelines: dict[str, TimelineDef] = {}
    offset = chunk.offset
    count = reader.read_uint32(offset)
    offset += 4

    for tl_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        tl_name = string_table[name_id]
        tl = TimelineDef(id=tl_id, name=tl_name)

        moment_count = reader.read_uint32(offset)
        offset += 4
        for _ in range(moment_count):
            step = reader.read_int32(offset); offset += 4
            code_id = reader.read_int32(offset); offset += 4
            code_offset = reader.read_int32(offset); offset += 4
            code_length = reader.read_int32(offset); offset += 4
            moment = TimelineMoment(
                step=step,
                code_id=code_id,
                code_offset=code_offset,
                code_length=code_length,
            )
            tl.moments.append(moment)

        timelines[tl_name] = tl

    return timelines
