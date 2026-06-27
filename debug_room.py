"""Debug GMS2.3 ROOM chunk format by dumping raw room data with correct field annotations."""
from pathlib import Path
from binary.reader import DataWinReader, locate_chunks
from binary.strg import StringTable

path = Path(r"D:\steam\steamapps\common\DELTARUNE\chapter5_windows\data.win")
reader = DataWinReader(path)
chunks = locate_chunks(reader)

# Parse STRG first for string lookups
strg = chunks.get("STRG")
st = StringTable()
if strg:
    st.parse(reader, strg)
    strings = st.strings
    string_count = len(strings)

room_chunk = chunks.get("ROOM")
print(f"ROOM chunk: offset=0x{room_chunk.offset:x}, size={room_chunk.size}")

# Read index table
count = reader.read_uint32(room_chunk.offset)
print(f"Room count: {count}")
offsets = []
for i in range(count):
    off = reader.read_uint32(room_chunk.offset + 4 + i * 4)
    offsets.append(off)
    print(f"  Room {i}: entry_offset=0x{off:x}")

# Dump header fields for first few rooms using correct GMS2.3 layout
for room_id in range(min(5, count)):
    entry_off = offsets[room_id]
    print(f"\n--- Room {room_id} @ 0x{entry_off:x} ---")

    # GMS2.3 room header (first 96 bytes)
    # [+0]=name_ptr [+4]=caption_ptr [+8]=width [+12]=height
    # [+16]=speed [+20]=persistent [+24]=bg_color [+28]=pad
    # [+32]=cc_id [+36]=flags
    name_ptr = reader.read_int32(entry_off + 0)
    caption_ptr = reader.read_int32(entry_off + 4)

    def read_cstr(ptr: int) -> str:
        if ptr > 0 and ptr < reader.size:
            return reader.read_cstring(ptr)
        return ""

    print(f"  [+0]  name_ptr=0x{name_ptr:x} -> {read_cstr(name_ptr)!r}")
    print(f"  [+4]  caption_ptr=0x{caption_ptr:x} -> {read_cstr(caption_ptr)!r}")
    print(f"  [+8]  width={reader.read_uint32(entry_off + 8)}")
    print(f"  [+12] height={reader.read_uint32(entry_off + 12)}")
    print(f"  [+16] speed={reader.read_uint32(entry_off + 16)}")
    print(f"  [+20] persistent={reader.read_bool(entry_off + 20)}")
    print(f"  [+24] bg_color=0x{reader.read_uint32(entry_off + 24):08x}")
    print(f"  [+28] padding=0x{reader.read_uint32(entry_off + 28):08x}")
    print(f"  [+32] creation_code_id={reader.read_int32(entry_off + 32)}")
    print(f"  [+36] flags=0x{reader.read_uint32(entry_off + 36):08x}")

    # Section pointers
    print(f"  [+40] bg_ptr=0x{reader.read_uint32(entry_off + 40):08x}")
    print(f"  [+44] view_ptr=0x{reader.read_uint32(entry_off + 44):08x}")
    print(f"  [+48] obj_ptr=0x{reader.read_uint32(entry_off + 48):08x}")
    print(f"  [+52] tile_ptr=0x{reader.read_uint32(entry_off + 52):08x}")
    print(f"  [+56] world={reader.read_bool(entry_off + 56)}")
    print(f"  [+60] physics_top={reader.read_uint32(entry_off + 60)}")
    print(f"  [+64] physics_left={reader.read_uint32(entry_off + 64)}")
    print(f"  [+68] physics_right={reader.read_uint32(entry_off + 68)}")
    print(f"  [+72] physics_bottom={reader.read_uint32(entry_off + 72)}")
    print(f"  [+76] gravity_x={reader.read_float(entry_off + 76)}")
    print(f"  [+80] gravity_y={reader.read_float(entry_off + 80)}")
    print(f"  [+84] meters_per_pixel={reader.read_float(entry_off + 84)}")
    print(f"  [+88] layers_ptr=0x{reader.read_uint32(entry_off + 88):08x}")
    print(f"  [+92] sequences_ptr=0x{reader.read_uint32(entry_off + 92):08x}")

    # Dump raw hex of first 128 bytes for verification
    raw = reader.read_bytes(entry_off, 128)
    print(f"  Raw hex @0x{entry_off:x}:")
    for i in range(0, len(raw), 16):
        hex_part = ' '.join(f'{b:02x}' for b in raw[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[i:i+16])
        print(f"    0x{entry_off+i:08x}: {hex_part:48s} {ascii_part}")

    # Follow layers_ptr to show layer structure
    layers_ptr = reader.read_uint32(entry_off + 88)
    if 0 < layers_ptr < reader.size:
        lcount = reader.read_uint32(layers_ptr)
        print(f"  Layers ({lcount}):")
        loff = layers_ptr + 4
        for li in range(min(lcount, 5)):
            lname_ptr = reader.read_int32(loff)
            lname_str = read_cstr(lname_ptr)
            ltype = reader.read_uint32(loff + 8)
            ldepth = reader.read_int32(loff + 12)
            print(f"    layer {li}: name={lname_str!r} type={ltype} depth={ldepth}")
            loff += 36
            if ltype == 2:  # Instances
                icount = reader.read_uint32(loff)
                print(f"      instances ({icount}):")
                ioff = loff + 4
                for _ in range(min(icount, 10)):
                    iid = reader.read_uint32(ioff)
                    print(f"        instance_id={iid}")
                    ioff += 4
                loff = ioff

reader.close()
