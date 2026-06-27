from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from core.cache import FileContentCache
from core.models import (
    DialogueEntry,
    FontInfo,
    ObjectEvent,
    ObjectInfo,
    ProjectIndex,
    Reference,
    ReferenceType,
    ResourceType,
    RoomInfo,
    RoomInstance,
    RoomView,
    ScriptInfo,
    SoundInfo,
    SourceLocation,
    SpriteInfo,
)
from core.parser import (
    extract_all_references_from_code,
    parse_object_file,
    parse_room_instances,
)


class ProjectIndexer:
    def __init__(self) -> None:
        self._cache = FileContentCache(capacity=10000)
        self._object_dir_names: set[str] = set()

    def index(self, project_path: Path) -> ProjectIndex:
        project_path = project_path.resolve()
        if not project_path.is_dir():
            raise NotADirectoryError(f"Project path is not a directory: {project_path}")

        index = ProjectIndex(project_path=project_path)
        index.game_name = project_path.name

        self._index_all_resources(project_path, index)
        self._index_objects(project_path, index)
        self._index_rooms(project_path, index)
        self._index_scripts(project_path, index)
        self._index_sprites(project_path, index)
        self._index_sounds(project_path, index)
        self._index_fonts(project_path, index)
        self._index_dialogues(project_path, index)
        self._index_timelines(project_path, index)
        self._index_sequences(project_path, index)

        return index

    def _read_file(self, path: Path) -> Optional[str]:
        return self._cache.read_file(path)

    def _index_all_resources(self, project_path: Path, index: ProjectIndex) -> None:
        alljsons_path = project_path / "allJsons.json"
        if alljsons_path.exists():
            content = self._read_file(alljsons_path)
            if content:
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        for item in data:
                            self._process_alljsons_item(item, index)
                    elif isinstance(data, dict):
                        for key, value in data.items():
                            self._process_alljsons_item(value, index, key)
                except json.JSONDecodeError:
                    pass

    def _process_alljsons_item(self, item: Any, index: ProjectIndex, name_hint: str = "") -> None:
        if isinstance(item, dict):
            name = item.get("name") or item.get("resourceName") or name_hint
            rtype = self._classify_resource(item)
            if name and rtype != ResourceType.UNKNOWN:
                index.all_resources[name] = rtype

    def _classify_resource(self, item: dict) -> ResourceType:
        mapping = {
            "obj": ResourceType.OBJECT,
            "room": ResourceType.ROOM,
            "scr": ResourceType.SCRIPT,
            "spr": ResourceType.SPRITE,
            "snd": ResourceType.SOUND,
            "font": ResourceType.FONT,
            "timeline": ResourceType.TIMELINE,
            "seq": ResourceType.SEQUENCE,
            "shader": ResourceType.SHADER,
            "path": ResourceType.PATH,
            "notes": ResourceType.NOTES,
            "bg": ResourceType.BACKGROUND,
        }
        type_str = str(item.get("resourceType", "")).lower()
        for prefix, rt in mapping.items():
            if type_str.startswith(prefix) or type_str == prefix:
                return rt
        name = str(item.get("name", ""))
        for prefix, rt in mapping.items():
            if name.startswith(prefix + "_") or name.startswith(prefix):
                return rt
        return ResourceType.UNKNOWN

    def _index_objects(self, project_path: Path, index: ProjectIndex) -> None:
        objects_dir = project_path / "objects"
        if objects_dir.is_dir():
            for obj_dir in objects_dir.iterdir():
                if obj_dir.is_dir():
                    self._index_object_from_dir(obj_dir, index)
                elif obj_dir.suffix == ".gml" or obj_dir.suffix == ".object.gml":
                    self._index_object_from_file(obj_dir, index)

    def _index_object_from_dir(self, obj_dir: Path, index: ProjectIndex) -> None:
        obj_name = obj_dir.name
        obj_info = ObjectInfo(name=obj_name, path=obj_dir)
        sprite_gml = obj_dir / "sprite.gml"
        if sprite_gml.exists():
            content = self._read_file(sprite_gml)
            if content:
                obj_info.sprite = content.strip()

        for event_file in obj_dir.glob("*.gml"):
            if event_file.stem == "sprite":
                continue
            content = self._read_file(event_file)
            if content is None:
                continue
            event_name = event_file.stem
            event_type = self._classify_event_name(event_name)
            obj_info.events[f"{event_type.name}_{event_name}"] = ObjectEvent(
                event_type=event_type,
                subtype=event_name,
                code=content,
            )

        index.objects[obj_name] = obj_info
        index.all_resources[obj_name] = ResourceType.OBJECT

    def _index_object_from_file(self, file_path: Path, index: ProjectIndex) -> None:
        content = self._read_file(file_path)
        if content is None:
            return
        obj_name = file_path.stem
        if obj_name.endswith(".object"):
            obj_name = obj_name[:-7]

        headers, events = parse_object_file(content, file_path)
        obj_info = ObjectInfo(
            name=obj_name,
            sprite=headers.get("sprite"),
            parent=headers.get("parent"),
            mask=headers.get("mask"),
            solid=headers.get("solid", "0") == "1",
            persistent=headers.get("persistent", "0") == "1",
            depth=int(headers.get("depth", "0")),
            visible=headers.get("visible", "1") != "0",
            path=file_path,
            events=events,
        )
        index.objects[obj_name] = obj_info
        index.all_resources[obj_name] = ResourceType.OBJECT

    def _classify_event_name(self, name: str) -> Any:
        from core.parser import EventType

        lower = name.lower()
        mapping = {
            "create": EventType.CREATE,
            "destroy": EventType.DESTROY,
            "step": EventType.STEP,
            "alarm": EventType.ALARM,
            "draw": EventType.DRAW,
            "draw_gui": EventType.DRAW_GUI,
            "keyboard": EventType.KEYBOARD,
            "keypress": EventType.KEY_PRESS,
            "keyrelease": EventType.KEY_RELEASE,
            "mouse": EventType.MOUSE,
            "collision": EventType.COLLISION,
            "other": EventType.OTHER,
        }
        for key, et in mapping.items():
            if lower.startswith(key):
                return et
        return EventType.UNKNOWN

    def _index_rooms(self, project_path: Path, index: ProjectIndex) -> None:
        rooms_dir = project_path / "rooms"
        if rooms_dir.is_dir():
            for room_file in rooms_dir.iterdir():
                if room_file.suffix in (".gml", ".room.gml", ".json"):
                    self._index_room_file(room_file, index)

    def _index_room_file(self, file_path: Path, index: ProjectIndex) -> None:
        content = self._read_file(file_path)
        if content is None:
            return
        room_name = file_path.stem
        if room_name.endswith(".room"):
            room_name = room_name[:-5]

        room_info = RoomInfo(name=room_name, path=file_path)

        if file_path.suffix == ".json":
            try:
                data = json.loads(content)
                room_info.width = data.get("width", 0)
                room_info.height = data.get("height", 0)
                room_info.speed = data.get("speed", 30)
                for inst_data in data.get("instances", []):
                    inst = RoomInstance(
                        object_name=inst_data.get("objectName", ""),
                        x=inst_data.get("x", 0),
                        y=inst_data.get("y", 0),
                        instance_id=inst_data.get("instanceId"),
                        creation_code=inst_data.get("creationCode"),
                    )
                    room_info.instances.append(inst)
            except json.JSONDecodeError:
                pass
        else:
            room_info.creation_code = content
            instances = parse_room_instances(content, file_path)
            for obj_name, x, y, code in instances:
                room_info.instances.append(RoomInstance(
                    object_name=obj_name, x=x, y=y, creation_code=code
                ))
            width_match = re.search(r"//\s*@width\s+(\d+)", content)
            if width_match:
                room_info.width = int(width_match.group(1))
            height_match = re.search(r"//\s*@height\s+(\d+)", content)
            if height_match:
                room_info.height = int(height_match.group(1))

        index.rooms[room_name] = room_info
        index.all_resources[room_name] = ResourceType.ROOM

    def _index_scripts(self, project_path: Path, index: ProjectIndex) -> None:
        scripts_dir = project_path / "scripts"
        if scripts_dir.is_dir():
            for script_file in scripts_dir.rglob("*.gml"):
                self._index_script_file(script_file, index)
        for script_file in project_path.glob("*.gml"):
            if script_file.stem.startswith("scr_") or script_file.stem.startswith("gml_"):
                self._index_script_file(script_file, index)

    def _index_script_file(self, file_path: Path, index: ProjectIndex) -> None:
        content = self._read_file(file_path)
        if content is None:
            return
        script_name = file_path.stem

        is_anonymous = script_name.startswith("gml_") or script_name.startswith("anon_") or script_name.startswith("Anonymous_")
        args: list[str] = []
        if not is_anonymous:
            arg_match = re.search(r"//\s*@param\s+(\w+)", content)
            while arg_match:
                args.append(arg_match.group(1))
                arg_match = re.search(r"//\s*@param\s+(\w+)", content, arg_match.end())

        script_info = ScriptInfo(
            name=script_name,
            code=content,
            path=file_path,
            arguments=args,
            is_anonymous=is_anonymous,
            parent_function=self._infer_parent_function(script_name, content),
        )
        index.scripts[script_name] = script_info
        index.all_resources[script_name] = ResourceType.SCRIPT

    def _infer_parent_function(self, name: str, code: str) -> Optional[str]:
        if name.startswith("gml_") or name.startswith("anon_"):
            parent_match = re.search(r"function\s+(\w+)", code)
            if parent_match:
                return parent_match.group(1)
        return None

    def _index_sprites(self, project_path: Path, index: ProjectIndex) -> None:
        sprites_dir = project_path / "sprites"
        if sprites_dir.is_dir():
            for sprite_dir in sprites_dir.iterdir():
                sprite_name = sprite_dir.name
                sprite_info = SpriteInfo(name=sprite_name, path=sprite_dir)
                sprite_file = sprite_dir / "sprite.png"
                if not sprite_file.exists():
                    sprite_file = sprite_dir / f"{sprite_name}.png"
                if sprite_file.exists():
                    sprite_info.path = sprite_file
                index.sprites[sprite_name] = sprite_info
                index.all_resources[sprite_name] = ResourceType.SPRITE

        sprite_json = project_path / "allSprites.json"
        if sprite_json.exists():
            content = self._read_file(sprite_json)
            if content:
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                name = item.get("name", "")
                                if name and name not in index.sprites:
                                    index.sprites[name] = SpriteInfo(
                                        name=name,
                                        width=item.get("width", 0),
                                        height=item.get("height", 0),
                                        frames=item.get("frames", 1),
                                    )
                                    index.all_resources[name] = ResourceType.SPRITE
                except json.JSONDecodeError:
                    pass

    def _index_sounds(self, project_path: Path, index: ProjectIndex) -> None:
        sounds_dir = project_path / "sounds"
        if sounds_dir.is_dir():
            for sound_dir in sounds_dir.iterdir():
                sound_name = sound_dir.name
                sound_info = SoundInfo(name=sound_name, path=sound_dir)
                for ext in (".wav", ".ogg", ".mp3", ".aiff"):
                    sf = sound_dir / f"{sound_name}{ext}"
                    if sf.exists():
                        sound_info.path = sf
                        break
                index.sounds[sound_name] = sound_info
                index.all_resources[sound_name] = ResourceType.SOUND

        sound_json = project_path / "allSounds.json"
        if sound_json.exists():
            content = self._read_file(sound_json)
            if content:
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                name = item.get("name", "")
                                if name and name not in index.sounds:
                                    index.sounds[name] = SoundInfo(
                                        name=name,
                                        type=item.get("type", ""),
                                        channels=item.get("channels", 1),
                                    )
                                    index.all_resources[name] = ResourceType.SOUND
                except json.JSONDecodeError:
                    pass

    def _index_fonts(self, project_path: Path, index: ProjectIndex) -> None:
        fonts_dir = project_path / "fonts"
        if fonts_dir.is_dir():
            for font_dir in fonts_dir.iterdir():
                font_name = font_dir.name
                font_info = FontInfo(name=font_name, path=font_dir)
                index.fonts[font_name] = font_info
                index.all_resources[font_name] = ResourceType.FONT

    def _index_dialogues(self, project_path: Path, index: ProjectIndex) -> None:
        alltexts_path = project_path / "allTexts.txt"
        if alltexts_path.exists():
            content = self._read_file(alltexts_path)
            if content:
                self._parse_dialogue_text(content, index, alltexts_path)

        code_paths = [
            project_path / "text" / "text.gml",
            project_path / "lang" / "text.gml",
        ]
        for tp in code_paths:
            if tp.exists():
                content = self._read_file(tp)
                if content:
                    self._parse_dialogue_code(content, index, tp)

    def _parse_dialogue_text(self, content: str, index: ProjectIndex, file_path: Path) -> None:
        sections = re.split(r"//\s*---+\s*|\f", content)
        current_id: Optional[str] = None

        for section in sections:
            lines = section.strip().split("\n")
            for line in lines:
                id_match = re.match(r"^\s*(#\w+|msg_\w+|str_\w+|txt_\w+)\s*$", line)
                if id_match:
                    current_id = id_match.group(1)
                    continue
                text_match = re.match(r'^\s*"((?:[^"\\]|\\.)*)"', line)
                if text_match and current_id:
                    text = text_match.group(1)
                    if current_id not in index.dialogues:
                        index.dialogues[current_id] = DialogueEntry(
                            text_id=current_id,
                            text=text,
                            file_path=file_path,
                        )

        if not sections:
            for match in re.finditer(r'"(msg_\w+|str_\w+|txt_\w+|#\w+)"\s*:\s*"((?:[^"\\]|\\.)*)"', content):
                text_id = match.group(1)
                text = match.group(2)
                if text_id not in index.dialogues:
                    index.dialogues[text_id] = DialogueEntry(
                        text_id=text_id, text=text, file_path=file_path
                    )

    def _parse_dialogue_code(self, content: str, index: ProjectIndex, file_path: Path) -> None:
        for match in re.finditer(r'(?:scr_Dialogue|scr_Dialogue_String|show_message|draw_text)\s*\(\s*"((?:[^"\\]|\\.)*)"', content):
            text = match.group(1)
            tid = f"msg_{hash(text) & 0xFFFFFFFF:08x}"
            if tid not in index.dialogues:
                index.dialogues[tid] = DialogueEntry(text_id=tid, text=text, file_path=file_path)

    def _index_timelines(self, project_path: Path, index: ProjectIndex) -> None:
        timelines_dir = project_path / "timelines"
        if timelines_dir.is_dir():
            for tl_file in timelines_dir.glob("*.gml"):
                content = self._read_file(tl_file)
                if content:
                    name = tl_file.stem
                    index.timelines[name] = content
                    index.all_resources[name] = ResourceType.TIMELINE

    def _index_sequences(self, project_path: Path, index: ProjectIndex) -> None:
        sequences_dir = project_path / "sequences"
        if sequences_dir.is_dir():
            for seq_file in sequences_dir.glob("*.gml"):
                content = self._read_file(seq_file)
                if content:
                    name = seq_file.stem
                    index.sequences[name] = content
                    index.all_resources[name] = ResourceType.SEQUENCE
