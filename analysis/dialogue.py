"""DialogueAnalyzer: dialogue string detection using resolver string refs."""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

from code.opcodes import Opcode


class DialogueAnalyzer:
    def __init__(self, game) -> None:
        self.game = game
        self.resolver = game.resolver
        self.dialogue_strings: dict[int, str] = {}
        self.dialogue_refs: dict[int, list[tuple[str, int]]] = defaultdict(list)
        self.dialogue_funcs: set[str] = set()

    def analyze(self) -> None:
        for name, func in self.game.functions.items():
            if "dialogue" in name.lower() or name in {
                "scr_Dialogue", "scr_Dialogue_String", "scr_Dialogue_Name",
                "show_message", "draw_text", "draw_text_ext",
            }:
                self.dialogue_funcs.add(name)

        for code_id, entry in self.game.code_entries.items():
            owner = self.resolver.owner_of(code_id)
            # Collect all PUSHSTR strings
            for instr in entry.instructions:
                if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                    s = self.game.string(instr.value_str_id)
                    if s and len(s) > 3:
                        self.dialogue_strings[instr.value_str_id] = s

            # Find dialogue function calls with preceding PUSHSTR args
            for i, instr in enumerate(entry.instructions):
                if instr.opcode not in (Opcode.CALL, Opcode.CALLV, Opcode.CALLVN):
                    continue
                if self._is_dialogue_call(instr, code_id):
                    str_ids = self._find_preceding_strings(entry.instructions, i)
                    for str_id in str_ids:
                        self.dialogue_refs[str_id].append((owner or f"code_{code_id}", i))

    def _is_dialogue_call(self, instr, code_id: int) -> bool:
        func_id = instr.value_func_id
        for name, func in self.game.functions.items():
            if func.id == func_id and name in self.dialogue_funcs:
                return True
        return False

    def _find_preceding_strings(self, instructions, call_idx: int) -> list[int]:
        str_ids: list[int] = []
        for j in range(max(0, call_idx - 5), call_idx):
            instr = instructions[j]
            if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                str_ids.append(instr.value_str_id)
        return str_ids[-3:] if str_ids else []

    def unused_dialogue(self) -> list[tuple[int, str]]:
        all_dialogue = set(self.dialogue_strings.keys())
        referenced = set(self.dialogue_refs.keys())
        unused = all_dialogue - referenced
        result = []
        for str_id in sorted(unused):
            result.append((str_id, self.dialogue_strings[str_id]))
        return result

    def dialogue_summary(self) -> dict:
        return {
            "total_dialogue_strings": len(self.dialogue_strings),
            "referenced_strings": len(self.dialogue_refs),
            "unused_strings": len(self.unused_dialogue()),
            "dialogue_functions": list(self.dialogue_funcs),
        }
