from __future__ import annotations

import mmap
import struct
from pathlib import Path
from typing import Optional


class DataWinReader:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self._file = open(self.path, "rb")
        self._data = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        self._size = len(self._data)

    def close(self) -> None:
        if self._data:
            self._data.close()
        if self._file:
            self._file.close()

    @property
    def size(self) -> int:
        return self._size

    def read_byte(self, offset: int) -> int:
        return self._data[offset]

    def read_int16(self, offset: int) -> int:
        return struct.unpack_from("<h", self._data, offset)[0]

    def read_uint16(self, offset: int) -> int:
        return struct.unpack_from("<H", self._data, offset)[0]

    def read_int32(self, offset: int) -> int:
        return struct.unpack_from("<i", self._data, offset)[0]

    def read_uint32(self, offset: int) -> int:
        return struct.unpack_from("<I", self._data, offset)[0]

    def read_int64(self, offset: int) -> int:
        return struct.unpack_from("<q", self._data, offset)[0]

    def read_uint64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self._data, offset)[0]

    def read_float(self, offset: int) -> float:
        return struct.unpack_from("<f", self._data, offset)[0]

    def read_double(self, offset: int) -> float:
        return struct.unpack_from("<d", self._data, offset)[0]

    def read_bool(self, offset: int) -> bool:
        return self._data[offset] != 0

    def read_bytes(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + size]

    def read_cstring(self, offset: int, max_len: int = 4096) -> str:
        end = offset
        while end < self._size and self._data[end] != 0 and (end - offset) < max_len:
            end += 1
        raw = self._data[offset:end]
        return raw.decode("utf-8", errors="replace")

    def read_fixed_string(self, offset: int, length: int) -> str:
        raw = self._data[offset : offset + length]
        null_pos = raw.find(b"\x00")
        if null_pos >= 0:
            raw = raw[:null_pos]
        return raw.decode("utf-8", errors="replace")

    def read_length_string(self, offset: int) -> tuple[str, int]:
        strlen = self.read_uint32(offset)
        start = offset + 4
        raw = self._data[start : start + strlen]
        result = raw.decode("utf-8", errors="replace")
        return result, 4 + strlen

    def read_pascal_string(self, offset: int) -> tuple[str, int]:
        strlen = self.read_byte(offset)
        start = offset + 1
        raw = self._data[start : start + strlen]
        result = raw.decode("utf-8", errors="replace")
        return result, 1 + strlen

    def read_guid(self, offset: int) -> str:
        raw = self.read_bytes(offset, 16)
        return "-".join(
            [
                raw[0:4].hex(),
                raw[4:6].hex(),
                raw[6:8].hex(),
                raw[8:10].hex(),
                raw[10:16].hex(),
            ]
        )

    def read_pointer(self, offset: int, base: int = 0) -> int:
        return self.read_uint32(offset)

    def skip(self, offset: int, count: int) -> int:
        return offset + count

    def align4(self, offset: int) -> int:
        return (offset + 3) & ~3

    def section(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + size]

    def find(self, pattern: bytes, start: int = 0) -> int:
        return self._data.find(pattern, start)

    def rfind(self, pattern: bytes, start: int = 0) -> int:
        return self._data.rfind(pattern, start)

    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        self.close()


class ChunkInfo:
    def __init__(self, tag: str, offset: int, size: int) -> None:
        self.tag = tag
        self.offset = offset
        self.size = size
        self.end = offset + size

    def __repr__(self) -> str:
        return f"Chunk({self.tag}, offset={self.offset}, size={self.size})"


def locate_chunks(reader: DataWinReader) -> dict[str, ChunkInfo]:
    chunks: dict[str, ChunkInfo] = {}
    offset = 0

    form_tag = reader.read_bytes(offset, 4)
    if form_tag == b"FORM":
        form_size = reader.read_uint32(offset + 4)
        offset += 8
    elif form_tag == b"WAD " or form_tag == b"WAD2":
        wad_size = reader.read_uint32(offset + 4)
        wad_unk = reader.read_uint32(offset + 8)
        offset += 12
    elif form_tag[:3] == b"PK\x03" or form_tag[:2] == b"\x1f\x8b":
        raise ValueError("Compressed data.win not supported (use UndertaleModTool to decompress)")
    else:
        raise ValueError(f"Unknown format: {form_tag!r}")

    while offset < reader.size - 8:
        tag = reader.read_bytes(offset, 4).decode("ascii", errors="replace")
        if tag == "TXTR":
            chunk_size = reader.read_uint32(offset + 4)
            chunks[tag] = ChunkInfo(tag, offset, chunk_size + 8)
            break
        chunk_size = reader.read_uint32(offset + 4)
        chunks[tag] = ChunkInfo(tag, offset + 8, chunk_size)
        offset += 8 + chunk_size
        offset = reader.align4(offset)

    return chunks
