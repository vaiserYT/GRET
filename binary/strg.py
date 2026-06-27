from __future__ import annotations

from binary.reader import DataWinReader, ChunkInfo


class StringTable:
    def __init__(self) -> None:
        self.strings: list[str] = []
        self._id_map: dict[str, int] = {}

    def __getitem__(self, idx: int) -> str:
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return f"<string_{idx}>"

    def __len__(self) -> int:
        return len(self.strings)

    def __iter__(self):
        return iter(self.strings)

    def id_of(self, s: str) -> int:
        return self._id_map.get(s, -1)

    def contains(self, s: str) -> bool:
        return s in self._id_map

    def parse(self, reader: DataWinReader, chunk: ChunkInfo) -> None:
        offset = chunk.offset
        count = reader.read_uint32(offset)
        offset += 4

        data_start = chunk.offset + 4 + count * 4
        data_offset = data_start
        chunk_end = chunk.offset + chunk.size

        # If data_start looks reasonable, use index-table format
        if data_start < chunk_end:
            offset = data_start
            for i in range(count):
                if offset + 4 > chunk_end:
                    break
                strlen = reader.read_uint32(offset)
                if strlen == 0 or strlen > chunk_end - offset - 4:
                    # Might be spurious - try to recover
                    self.strings.append("")
                    offset += 4
                    continue
                offset += 4
                raw = reader.read_bytes(offset, strlen)
                s = raw.decode("utf-8", errors="replace")
                self.strings.append(s)
                offset += strlen
                offset = reader.align4(offset)
        else:
            # Fallback: try reading length-prefixed strings inline
            offset = chunk.offset + 4
            for _ in range(count):
                if offset + 4 > chunk_end:
                    break
                strlen = reader.read_uint32(offset)
                if strlen == 0 or strlen > 4096:
                    offset += 4
                    continue
                offset += 4
                raw = reader.read_bytes(offset, strlen)
                s = raw.decode("utf-8", errors="replace")
                self.strings.append(s)
                offset += strlen
                offset = reader.align4(offset)

        self._id_map = {s: i for i, s in enumerate(self.strings)}

    def query(self, pattern: str) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for i, s in enumerate(self.strings):
            if pattern.lower() in s.lower():
                results.append((i, s))
        return results

    def prefixed(self, prefix: str) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for i, s in enumerate(self.strings):
            if s.startswith(prefix):
                results.append((i, s))
        return results

    def all_with_suffix(self, suffix: str) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for i, s in enumerate(self.strings):
            if s.endswith(suffix):
                results.append((i, s))
        return results
