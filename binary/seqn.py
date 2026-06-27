from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo
from model.sequence import SequenceDef, SequenceTrack, SequenceKeyframe


def parse_seqn(reader: DataWinReader, chunk: ChunkInfo, string_table) -> dict[str, SequenceDef]:
    sequences: dict[str, SequenceDef] = {}
    if chunk.size < 8:
        return sequences

    offset = chunk.offset
    count = reader.read_uint32(offset)
    offset += 4

    for seq_id in range(count):
        if offset + 12 > chunk.end:
            break

        name_id = reader.read_uint32(offset); offset += 4
        length = reader.read_float(offset); offset += 4

        seq_name = string_table[name_id]
        seq = SequenceDef(id=seq_id, name=seq_name, length=length)

        track_count = reader.read_uint32(offset)
        offset += 4

        for _ in range(track_count):
            if offset + 12 > chunk.end:
                break

            track_name_id = reader.read_uint32(offset); offset += 4
            track_type = reader.read_int32(offset); offset += 4
            track_target = reader.read_int32(offset); offset += 4

            track = SequenceTrack(
                name=string_table[track_name_id] if track_name_id >= 0 else "",
                type=track_type,
                target_id=track_target,
            )

            kf_count = reader.read_uint32(offset)
            offset += 4
            for _ in range(kf_count):
                kf_time = reader.read_float(offset); offset += 4
                kf_value = reader.read_float(offset); offset += 4
                kf_curve = reader.read_int32(offset); offset += 4

                kf = SequenceKeyframe(time=kf_time, value=kf_value, curve=kf_curve)
                track.keyframes.append(kf)

            seq.tracks.append(track)

        sequences[seq_name] = seq

    return sequences
