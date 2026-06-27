from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class VariableKind(IntEnum):
    LOCAL = 0
    GLOBAL = 1
    INSTANCE = 2
    BUILTIN = 3


@dataclass
class VariableDef:
    id: int
    name: str
    kind: VariableKind = VariableKind.GLOBAL
    is_array: bool = False
    init_value: str = ""
    read_count: int = 0
    write_count: int = 0

    @property
    def display_name(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.id)
