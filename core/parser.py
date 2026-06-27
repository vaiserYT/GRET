from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, Optional

from core.models import (
    EventType,
    ObjectEvent,
    Reference,
    ReferenceType,
    ResourceType,
    SourceLocation,
)


EVENT_HEADER_RE = re.compile(r"//[/\s]*@event\s+(\w+)(?:\s+(.+))?", re.IGNORECASE)
OBJECT_HEADER_RE = re.compile(r"//[/\s]*@(sprite|parent|mask|solid|persistent|depth|visible)\s+(.+)", re.IGNORECASE)

INSTANCE_CREATE_RE = re.compile(
    r"(?:instance_create[_\w]*)\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\s*\)"
)
INSTANCE_CREATE_LAYER_RE = re.compile(
    r"instance_create_layer\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\s*\)"
)
WITH_RE = re.compile(r"with\s*\(\s*(\w+(?:\s*\[\s*\d+\s*\])?)\s*\)")
OBJECT_INDEX_RE = re.compile(r"(\w+)\.object_index\b")
EVENT_INHERITED_RE = re.compile(r"event_inherited\s*\(\s*\)")
SCRIPT_EXECUTE_RE = re.compile(r"script_execute\s*\(\s*(\w+)")
METHOD_RE = re.compile(r"method\s*\(\s*(\w+)")
ROOM_GOTO_RE = re.compile(r"room_goto(?:_next|_previous|_restart)?\s*\(\s*(\w*)\s*\)")
ROOM_GOTO_NEXT_RE = re.compile(r"room_goto_next\s*\(\s*\)")
ROOM_RESTART_RE = re.compile(r"room_restart\s*\(\s*\)")
ROOM_GOTO_PREVIOUS_RE = re.compile(r"room_goto_previous\s*\(\s*\)")

GLOBAL_FLAG_RE = re.compile(r"global\.flag\s*\[\s*(\d+)\s*\]")
SCR_FLAG_GET_RE = re.compile(r"scr_flag_get\s*\(\s*(\d+)")
SCR_FLAG_SET_RE = re.compile(r"scr_flag_set\s*\(\s*(\d+)\s*,")
GLOBAL_PLOT_RE = re.compile(r"global\.plot\b")
GLOBAL_CHAPTER_RE = re.compile(r"global\.chapter\b")
GLOBAL_ROUTE_RE = re.compile(r"global\.route\b")
GLOBAL_FILECHOICE_RE = re.compile(r"global\.filechoice\b")

SWITCH_PLOT_RE = re.compile(r"switch\s*\(\s*global\.plot\s*\)")
CASE_RE = re.compile(r"case\s+(-?\d+)\s*:")

FUNCTION_CALL_RE = re.compile(r"(\w+)\s*\(")
STRING_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

ASSIGNMENT_RE = re.compile(r"(\w+(?:\.\w+)*)\s*=\s*(.+?)(?:;|$)")
ARRAY_ACCESS_RE = re.compile(r"(\w+)\s*\[\s*(\w+)\s*\]")

GLOBAL_VAR_SET_RE = re.compile(r"global\.(\w+)\s*=")
GLOBAL_VAR_GET_RE = re.compile(r"global\.(\w+)\b(?!\s*=)")

AUDIO_PLAY_RE = re.compile(r"audio_play_sound\s*\(\s*(\w+)")
AUDIO_PLAY_EXT_RE = re.compile(r"audio_play_sound_at\s*\(\s*(\w+)")
SPRITE_SET_RE = re.compile(r"(?:sprite_index|mask_index)\s*=\s*(\w+)")
PARTICLE_CREATE_RE = re.compile(r"(?:part_type_create|part_system_create|effect_create)\s*\(\s*(?:\w+\s*,)*\s*(\w+)\s*\)")


def parse_event_type(name: str) -> EventType:
    mapping = {
        "create": EventType.CREATE,
        "destroy": EventType.DESTROY,
        "step": EventType.STEP,
        "alarm": EventType.ALARM,
        "draw": EventType.DRAW,
        "draw_gui": EventType.DRAW_GUI,
        "drawgui": EventType.DRAW_GUI,
        "keyboard": EventType.KEYBOARD,
        "keypress": EventType.KEY_PRESS,
        "keyrelease": EventType.KEY_RELEASE,
        "mouse": EventType.MOUSE,
        "collision": EventType.COLLISION,
        "other": EventType.OTHER,
        "roomstart": EventType.ROOM_START,
        "room_start": EventType.ROOM_START,
        "roomend": EventType.ROOM_END,
        "room_end": EventType.ROOM_END,
        "animationend": EventType.ANIMATION_END,
        "animation_end": EventType.ANIMATION_END,
        "cleanup": EventType.CLEANUP,
        "user": EventType.USER,
    }
    return mapping.get(name.lower(), EventType.UNKNOWN)


def parse_object_file(content: str, file_path: Path) -> tuple[dict[str, str], dict[str, ObjectEvent]]:
    headers: dict[str, str] = {}
    events: dict[str, ObjectEvent] = {}
    lines = content.split("\n")
    current_event: Optional[str] = None
    current_code: list[str] = []
    current_start = 0

    for i, line in enumerate(lines, 1):
        header_match = OBJECT_HEADER_RE.match(line)
        if header_match:
            headers[header_match.group(1).lower()] = header_match.group(2).strip()
            continue

        event_match = EVENT_HEADER_RE.match(line)
        if event_match:
            if current_event is not None:
                event_type = parse_event_type(current_event.split("_")[0])
                subtype = current_event.split("_", 1)[1] if "_" in current_event else None
                events[current_event] = ObjectEvent(
                    event_type=event_type,
                    subtype=subtype,
                    code="\n".join(current_code),
                    line_start=current_start,
                    line_end=i - 1,
                )
            current_event = f"{event_match.group(1).lower()}_{event_match.group(2) or ''}".strip("_")
            current_code = []
            current_start = i
            continue

        if current_event is not None:
            current_code.append(line)

    if current_event is not None:
        event_type_val = parse_event_type(current_event.split("_")[0])
        subtype_val = current_event.split("_", 1)[1] if "_" in current_event else None
        events[current_event] = ObjectEvent(
            event_type=event_type_val,
            subtype=subtype_val,
            code="\n".join(current_code),
            line_start=current_start,
            line_end=len(lines),
        )

    return headers, events


def extract_string_literals(code: str) -> list[str]:
    return STRING_LITERAL_RE.findall(code)


def extract_function_calls(code: str) -> list[tuple[str, int]]:
    calls: list[tuple[str, int]] = []
    for match in FUNCTION_CALL_RE.finditer(code):
        func_name = match.group(1)
        if func_name and not func_name.startswith(("//", "#")):
            line_num = code[: match.start()].count("\n") + 1
            calls.append((func_name, line_num))
    return calls


def extract_flag_references(code: str, source: SourceLocation) -> list[Reference]:
    refs: list[Reference] = []
    for match in GLOBAL_FLAG_RE.finditer(code):
        flag_idx = int(match.group(1))
        before = code[max(0, match.start() - 10) : match.start()]
        is_set = "=" in before and "==" not in before
        refs.append(Reference(
            source=source,
            target=str(flag_idx),
            ref_type=ReferenceType.WRITE if is_set else ReferenceType.READ,
        ))
    for match in SCR_FLAG_GET_RE.finditer(code):
        refs.append(Reference(
            source=source,
            target=match.group(1),
            ref_type=ReferenceType.READ,
        ))
    for match in SCR_FLAG_SET_RE.finditer(code):
        refs.append(Reference(
            source=source,
            target=match.group(1),
            ref_type=ReferenceType.WRITE,
        ))
    return refs


def extract_room_transitions(code: str, source: SourceLocation) -> list[tuple[str, str]]:
    transitions: list[tuple[str, str]] = []
    for match in ROOM_GOTO_RE.finditer(code):
        room_name = match.group(1)
        if room_name:
            transitions.append((room_name, "room_goto"))
    if ROOM_GOTO_NEXT_RE.search(code):
        transitions.append(("__next__", "room_goto_next"))
    if ROOM_RESTART_RE.search(code):
        transitions.append(("__current__", "room_restart"))
    if ROOM_GOTO_PREVIOUS_RE.search(code):
        transitions.append(("__previous__", "room_goto_previous"))
    return transitions


def extract_object_creations(code: str, source: SourceLocation) -> list[str]:
    objects: list[str] = []
    for match in INSTANCE_CREATE_RE.finditer(code):
        obj_name = match.group(3).strip()
        if obj_name and not obj_name[0].isdigit():
            objects.append(obj_name)
    for match in INSTANCE_CREATE_LAYER_RE.finditer(code):
        obj_name = match.group(4).strip()
        if obj_name and not obj_name[0].isdigit():
            objects.append(obj_name)
    for match in WITH_RE.finditer(code):
        obj_name = match.group(1).strip()
        if obj_name and not obj_name[0].isdigit():
            objects.append(obj_name)
    for match in OBJECT_INDEX_RE.finditer(code):
        obj_name = match.group(1).strip()
        if obj_name and obj_name not in ("self", "other", "all", "noone"):
            objects.append(obj_name)
    return objects


def extract_script_calls(code: str) -> list[str]:
    scripts: list[str] = []
    for match in SCRIPT_EXECUTE_RE.finditer(code):
        scripts.append(match.group(1))
    for match in METHOD_RE.finditer(code):
        scripts.append(match.group(1))
    func_calls = extract_function_calls(code)
    for func_name, _ in func_calls:
        if func_name.startswith("scr_"):
            scripts.append(func_name)
    return scripts


def extract_sprite_references(code: str) -> list[str]:
    sprites: list[str] = []
    for match in SPRITE_SET_RE.finditer(code):
        sprites.append(match.group(1))
    return sprites


def extract_sound_references(code: str) -> list[str]:
    sounds: list[str] = []
    for match in AUDIO_PLAY_RE.finditer(code):
        sounds.append(match.group(1))
    for match in AUDIO_PLAY_EXT_RE.finditer(code):
        sounds.append(match.group(1))
    return sounds


def extract_switch_cases(code: str) -> list[int]:
    cases: list[int] = []
    for match in CASE_RE.finditer(code):
        cases.append(int(match.group(1)))
    return cases


def extract_global_var_refs(code: str, source: SourceLocation) -> list[Reference]:
    refs: list[Reference] = []
    for match in GLOBAL_VAR_SET_RE.finditer(code):
        refs.append(Reference(source=source, target=f"global.{match.group(1)}", ref_type=ReferenceType.WRITE))
    for match in GLOBAL_VAR_GET_RE.finditer(code):
        refs.append(Reference(source=source, target=f"global.{match.group(1)}", ref_type=ReferenceType.READ))
    return refs


def parse_room_instances(content: str, file_path: Path) -> list[tuple[str, int, int, Optional[str]]]:
    instances: list[tuple[str, int, int, Optional[str]]] = []
    current_obj: Optional[str] = None
    current_x = 0
    current_y = 0
    current_code: Optional[str] = None

    instance_header = re.compile(r"//\s*Instance:\s*(\w+)\s*\((\d+)\s*,\s*(\d+)\)")
    creation_code_start = re.compile(r"//\s*Data:")
    creation_code_end = re.compile(r"//\s*End of instance")

    lines = content.split("\n")
    in_creation_code = False
    code_lines: list[str] = []

    for line in lines:
        inst_match = instance_header.match(line)
        if inst_match:
            if current_obj is not None:
                instances.append((current_obj, current_x, current_y, current_code))
            current_obj = inst_match.group(1)
            current_x = int(inst_match.group(2))
            current_y = int(inst_match.group(3))
            current_code = None
            in_creation_code = False
            code_lines = []
            continue

        if in_creation_code:
            if creation_code_end.match(line):
                current_code = "\n".join(code_lines) if code_lines else None
                in_creation_code = False
            else:
                code_lines.append(line)
            continue

        if creation_code_start.match(line):
            in_creation_code = True
            code_lines = []
            continue

    if current_obj is not None:
        instances.append((current_obj, current_x, current_y, current_code))

    return instances


def extract_all_references_from_code(
    code: str,
    source: SourceLocation,
) -> dict[str, list[Reference]]:
    result: dict[str, list[Reference]] = {}

    for obj_name in extract_object_creations(code, source):
        result.setdefault("objects", []).append(
            Reference(source=source, target=obj_name, ref_type=ReferenceType.DYNAMIC)
        )

    for script_name in extract_script_calls(code):
        result.setdefault("scripts", []).append(
            Reference(source=source, target=script_name, ref_type=ReferenceType.CALL)
        )

    for room_name, trans_type in extract_room_transitions(code, source):
        result.setdefault("rooms", []).append(
            Reference(source=source, target=room_name, ref_type=ReferenceType.TRANSITION)
        )

    for sprite_name in extract_sprite_references(code):
        result.setdefault("sprites", []).append(
            Reference(source=source, target=sprite_name, ref_type=ReferenceType.REFERENCE)
        )

    for sound_name in extract_sound_references(code):
        result.setdefault("sounds", []).append(
            Reference(source=source, target=sound_name, ref_type=ReferenceType.REFERENCE)
        )

    flag_refs = extract_flag_references(code, source)
    for ref in flag_refs:
        result.setdefault("flags", []).append(ref)

    return result
