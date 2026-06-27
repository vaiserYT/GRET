from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.path_ import PathDef, PathPoint


def parse_path(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, PathDef]:
    paths: dict[str, PathDef] = {}
    offset = chunk.offset
    count = reader.read_uint32(offset)
    offset += 4

    for path_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        smooth = reader.read_bool(offset); offset += 1
        closed = reader.read_bool(offset); offset += 1
        precision = reader.read_int32(offset); offset += 4

        path_name = string_table[name_id]
        p = PathDef(id=path_id, name=path_name, smooth=smooth, closed=closed, precision=precision)

        point_count = reader.read_uint32(offset)
        offset += 4
        for _ in range(point_count):
            pt = PathPoint()
            pt.x = reader.read_float(offset); offset += 4
            pt.y = reader.read_float(offset); offset += 4
            pt.speed = reader.read_float(offset); offset += 4
            p.points.append(pt)

        paths[path_name] = p

    return paths
