"""
this script is hardcoded for aarch64 static ELFs
"""

import sys

with open(sys.argv[1], "rb") as inf:
	orig = inf.read()

# strip section headers
shoff = int.from_bytes(orig[0x28:0x28+8], "little")

truncated = orig[:shoff]

print(f"trimmed {len(orig) - len(truncated)} bytes ({len(orig)} -> {len(truncated)})")

with open(sys.argv[2], "wb") as outf:
	outf.write(truncated)
