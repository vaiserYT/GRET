from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.function import FunctionDef, FunctionArg


def parse_func(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, FunctionDef]:
    functions: dict[str, FunctionDef] = {}
    offset = chunk.offset

    count = reader.read_uint32(offset)
    offset += 4

    for func_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        code_id = reader.read_int32(offset); offset += 4
        code_offset = reader.read_int32(offset); offset += 4
        code_length = reader.read_int32(offset); offset += 4
        owner_id = reader.read_int32(offset); offset += 4
        owner_type = reader.read_int32(offset); offset += 4
        arg_count = reader.read_uint32(offset); offset += 4
        locals_count = reader.read_uint32(offset); offset += 4

        func_name = string_table[name_id]
        func = FunctionDef(
            id=func_id,
            name=func_name,
            code_id=code_id,
            code_offset=code_offset,
            code_length=code_length,
            owner_id=owner_id,
            owner_type=owner_type,
            arg_count=arg_count,
            locals_count=locals_count,
        )

        for _ in range(arg_count):
            arg_name_id = reader.read_uint32(offset); offset += 4
            default_val = reader.read_int32(offset); offset += 4
            has_default = reader.read_bool(offset); offset += 1
            offset += 3

            arg = FunctionArg(
                name=string_table[arg_name_id] if arg_name_id >= 0 else f"arg_{_}",
                default_value=default_val,
                has_default=has_default,
            )
            func.args.append(arg)

        is_static = reader.read_bool(offset); offset += 1
        is_constructor = reader.read_bool(offset); offset += 1
        return_type = reader.read_int32(offset); offset += 4
        func.is_static = is_static
        func.is_constructor = is_constructor
        func.return_type = return_type

        functions[func_name] = func

    return functions
