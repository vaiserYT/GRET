from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.variable import VariableDef, VariableKind


def parse_vari(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, VariableDef]:
    variables: dict[str, VariableDef] = {}
    offset = chunk.offset

    count = reader.read_uint32(offset)
    offset += 4

    for var_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        var_kind = reader.read_int32(offset); offset += 4
        is_array = reader.read_bool(offset); offset += 1
        offset += 3
        init_val_id = reader.read_int32(offset); offset += 4

        var_name = string_table[name_id]
        init_val = string_table[init_val_id] if init_val_id >= 0 else ""

        var = VariableDef(
            id=var_id,
            name=var_name,
            kind=VariableKind(var_kind),
            is_array=is_array,
            init_value=init_val,
        )
        variables[var_name] = var

    return variables
