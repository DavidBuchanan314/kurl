"""
this script is hardcoded for aarch64 static ELFs with a single load segment
"""

import sys

with open(sys.argv[1], "rb") as inf:
	orig = bytearray(inf.read())

phoff = int.from_bytes(orig[0x20:0x20+8], "little")
orig[0x28:0x28+14] = bytes(14) # nullify shoff
orig[0x3a:0x40] = bytes(6)

print(f"[*] phoff = {hex(phoff)}")

# inspect the first program header
load_offset = int.from_bytes(orig[phoff+8:phoff+8+8], "little")
file_size = int.from_bytes(orig[phoff+32:phoff+32+8], "little")

load_end = load_offset + file_size

print(f"[*] last loaded byte @ {hex(load_end)}")

truncated = orig[:load_end].rstrip(b"\x00") # strip trailing zeroes

print(f"[+] trimmed {len(orig) - len(truncated)} bytes ({len(orig)} -> {len(truncated)})")

# trim original ELF headers!
truncated = truncated[0x10000:]

# TODO: fix up p_filesz and p_memsz

with open(sys.argv[2], "wb") as outf:
	outf.write(truncated)
