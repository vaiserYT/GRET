from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.sound import SoundDef


def parse_sond(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, SoundDef]:
    sounds: dict[str, SoundDef] = {}
    offset = chunk.offset
    count = reader.read_uint32(offset)
    offset += 4

    for snd_id in range(count):
        name_id = reader.read_uint32(offset); offset += 4
        sound_type = reader.read_int32(offset); offset += 4
        file_id = reader.read_uint32(offset); offset += 4
        volume = reader.read_float(offset); offset += 4
        pitch = reader.read_float(offset); offset += 4
        preload = reader.read_bool(offset); offset += 1
        offset += 3

        audio_group = reader.read_int32(offset); offset += 4
        data_offset = reader.read_int32(offset); offset += 4
        data_size = reader.read_int32(offset); offset += 4
        bitrate = reader.read_int32(offset); offset += 4
        compression = reader.read_int32(offset); offset += 4
        effects = reader.read_int32(offset); offset += 4

        snd_name = string_table[name_id]
        snd_file = string_table[file_id] if file_id >= 0 else ""
        sound = SoundDef(id=snd_id, name=snd_name)
        sound.type = sound_type
        sound.file = snd_file
        sound.volume = volume
        sound.pitch = pitch
        sound.preload = preload
        sound.audio_group = audio_group
        sound.data_offset = data_offset
        sound.data_size = data_size
        sound.bitrate = bitrate
        sound.compression = compression
        sound.effects = effects

        sounds[snd_name] = sound

    return sounds
