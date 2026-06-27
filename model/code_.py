from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VMInstruction:
    opcode: int
    instruction_type: int
    kind: int
    dest: int
    arg_count: int
    extra: int
    raw_bytes: bytes = b""
    offset: int = 0

    # Decoded values
    value_int: int = 0
    value_float: float = 0.0
    value_str: str = ""
    value_str_id: int = -1
    value_func_id: int = -1
    value_variable_id: int = -1
    value_arg_count: int = 0

    # Flow control
    jump_offset: int = 0
    jump_target: int = 0


@dataclass
class CodeEntry:
    id: int
    offset: int            # absolute file offset of bytecode data
    length: int            # bytecode length (for the entire blob)
    name: str = ""         # parsed function name (e.g. "gml_Script_scr_foo")
    name_str_off: int = 0  # file offset to name in STRG data area

    # v15+ entry header fields
    entry_off: int = 0              # file offset of this entry's 20-byte header
    bytecode_rel_addr: int = 0      # relative address to bytecode blob from entry end
    bytecode_offset_within_blob: int = 0  # offset within blob (0 = parent, >0 = child)

    instructions: list[VMInstruction] = field(default_factory=list)
    locals_count: int = 0
    arguments_count: int = 0

    # Analysis results
    # calls: (func_id_or_code_id, arg_count, call_type)
    #   call_type 0=normal(FUNC idx), 1=builtin, 2=script(CODE idx), 3=method, 4=constructor
    calls: list[tuple[int, int, int]] = field(default_factory=list)
    string_refs: list[int] = field(default_factory=list)
    flag_refs: list[tuple[int, bool]] = field(default_factory=list)
    variable_refs: list[tuple[int, int]] = field(default_factory=list)
    sprite_refs: list[int] = field(default_factory=list)
    sound_refs: list[int] = field(default_factory=list)
    room_refs: list[int] = field(default_factory=list)
    object_refs: list[int] = field(default_factory=list)
    script_refs: list[int] = field(default_factory=list)

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    def has_calls(self) -> bool:
        return len(self.calls) > 0

    def has_strings(self) -> bool:
        return len(self.string_refs) > 0
