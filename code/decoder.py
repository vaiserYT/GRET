from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from code.opcodes import (
    Opcode,
    VM_HEADER_SIZE,
    is_call,
    is_jump,
    is_push,
    opcode_name,
)
from model.code_ import CodeEntry, VMInstruction


# GMS 2.3+ instruction sizes for immediates after header
# Returns (has_function_id, has_variable_id, has_string_id, has_jump_offset, extra_size)
def instruction_immediate_info(opcode: int) -> tuple[bool, bool, bool, bool, int]:
    if opcode == Opcode.PUSHI:
        return (False, False, False, False, 4)  # 4-byte int
    if opcode == Opcode.PUSHF:
        return (False, False, False, False, 8)  # 8-byte double
    if opcode == Opcode.PUSHSTR:
        return (False, False, True, False, 4)  # string ID
    if opcode in (Opcode.CALL, Opcode.CALLV, Opcode.CALLVN):
        return (True, False, False, False, 0)  # function ID
    if opcode == Opcode.NEW_OBJECT:
        return (True, False, False, False, 0)  # function ID
    if opcode in (Opcode.GOTO,):
        return (False, False, False, True, 4)  # jump offset
    if opcode in (Opcode.IF,):
        return (False, False, False, True, 4)  # jump offset
    if opcode in (Opcode.SWITCH,):
        return (False, False, False, False, 0)  # followed by case table
    if opcode in (Opcode.PUSH, Opcode.PUSHLOC, Opcode.PUSHGLB, Opcode.PUSHBLTN):
        return (False, True, False, False, 0)  # variable ID
    if opcode in (Opcode.PUSHENV, Opcode.POPENV):
        return (False, False, False, False, 4)  # count
    if opcode in (Opcode.INSTANTIATE,):
        return (False, False, False, False, 4)  # object ID
    if opcode in (Opcode.CONV,):
        return (False, False, False, False, 0)
    if opcode == Opcode.NOP:
        return (False, False, False, False, 0)
    return (False, False, False, False, 0)


def decode_instructions(
    reader: DataWinReader,
    code_offset: int,
    code_length: int,
    string_table,
    function_map: dict[str, int],
    variable_map: dict[str, int],
) -> list[VMInstruction]:
    instructions: list[VMInstruction] = []
    offset = code_offset
    end = code_offset + code_length

    while offset < end:
        if offset + VM_HEADER_SIZE > end:
            break

        raw_header = reader.read_bytes(offset, VM_HEADER_SIZE)
        instr_offset = offset  # save instruction start
        opcode = raw_header[0]
        inst_type = raw_header[1]
        kind = raw_header[2]
        dest = raw_header[3]
        arg_count = raw_header[4]
        extra = raw_header[5]
        offset += VM_HEADER_SIZE

        instr = VMInstruction(
            opcode=opcode,
            instruction_type=inst_type,
            kind=kind,
            dest=dest,
            arg_count=arg_count,
            extra=extra,
            raw_bytes=raw_header,
            offset=instr_offset,
        )

        has_func, has_var, has_str, has_jump, extra_size = instruction_immediate_info(opcode)

        if has_func:
            if offset + 4 <= end:
                func_id = reader.read_int32(offset)
                instr.value_func_id = func_id
                offset += 4
                if opcode in (Opcode.CALL, Opcode.CALLV, Opcode.CALLVN) and offset + 4 <= end:
                    instr.value_arg_count = arg_count

        if has_var:
            if offset + 4 <= end:
                var_id = reader.read_int32(offset)
                instr.value_variable_id = var_id
                offset += 4

        if has_str:
            if offset + 4 <= end:
                str_id = reader.read_int32(offset)
                instr.value_str_id = str_id
                instr.value_str = string_table[str_id] if 0 <= str_id < len(string_table) else f"<str_{str_id}>"
                offset += 4

        if has_jump:
            if offset + 4 <= end:
                jump_off = reader.read_int32(offset)
                instr.jump_offset = jump_off
                instr.jump_target = offset + jump_off
                offset += 4

        if extra_size > 0:
            if opcode == Opcode.PUSHI:
                if offset + 4 <= end:
                    instr.value_int = reader.read_int32(offset)
                    offset += 4
            elif opcode == Opcode.PUSHF:
                if offset + 8 <= end:
                    instr.value_float = reader.read_double(offset)
                    offset += 8
            elif opcode in (Opcode.PUSHENV, Opcode.POPENV):
                if offset + 4 <= end:
                    instr.value_int = reader.read_int32(offset)
                    offset += 4
            elif opcode == Opcode.INSTANTIATE:
                if offset + 4 <= end:
                    instr.value_int = reader.read_int32(offset)
                    offset += 4
            else:
                offset += extra_size

        instructions.append(instr)

    return instructions


def decode_code_entry(
    reader: DataWinReader,
    entry_id: int,
    entry_offset: int,
    entry_length: int,
    string_table,
    function_map: dict[str, int],
    variable_map: dict[str, int],
) -> CodeEntry:
    instructions = decode_instructions(
        reader, entry_offset, entry_length,
        string_table, function_map, variable_map,
    )

    entry = CodeEntry(
        id=entry_id,
        offset=entry_offset,
        length=entry_length,
        instructions=instructions,
    )

    str_count = len(string_table)

    for instr in instructions:
        if is_call(instr.opcode) and instr.value_func_id >= 0:
            entry.calls.append((instr.value_func_id, instr.value_arg_count, instr.instruction_type))
        if instr.opcode == Opcode.PUSHSTR and 0 <= instr.value_str_id < str_count:
            entry.string_refs.append(instr.value_str_id)
        if instr.opcode == Opcode.PUSHBLTN and instr.value_variable_id >= 0:
            entry.variable_refs.append((instr.value_variable_id, 0))

    return entry


def parse_code(
    reader: DataWinReader,
    chunk: ChunkInfo,
    string_table,
    function_map: dict[str, int],
    variable_map: dict[str, int],
) -> dict[int, CodeEntry]:
    entries: dict[int, CodeEntry] = {}
    offset = chunk.offset

    count = reader.read_uint32(offset)
    offset += 4

    for entry_id in range(count):
        code_offset = reader.read_int32(offset); offset += 4
        code_length = reader.read_int32(offset); offset += 4
        if code_length == 0:
            continue

        entry = decode_code_entry(
            reader, entry_id, chunk.offset + code_offset, code_length,
            string_table, function_map, variable_map,
        )
        entries[entry_id] = entry

    return entries
