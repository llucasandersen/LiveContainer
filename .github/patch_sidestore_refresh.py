"""Fail closed on invalid ASN.1 lengths in the pinned SideStore nightly.

Four device reports identify CodeSignKit.ASN1Helper.parseTLV + 0x438.
SideStore tries multiple embedded-P12 passwords; invalid plaintext must return
nil so the existing caller can try the next password, rather than trap.
Only the negative-range and length-addition-overflow exits change. Successful
certificate parsing and signature verification are untouched.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

UUID = bytes.fromhex("14da04f378903350a6da9bdabb337122")
PATCHES = {0x715478: 0x715484, 0x7154F0: 0x715484}


def patch(path):
    path = Path(path)
    data = bytearray(path.read_bytes())
    assert struct.unpack_from("<I", data)[0] == 0xFEEDFACF, "Expected thin Mach-O"
    offset = 32
    text = None
    uuid = None
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, size = struct.unpack_from("<II", data, offset)
        if command == 0x1B:
            uuid = bytes(data[offset + 8:offset + 24])
        if command == 0x19 and data[offset + 8:offset + 24].rstrip(b"\0") == b"__TEXT":
            text = struct.unpack_from("<QQQQ", data, offset + 24)
        offset += size
    assert uuid == UUID, "SideStore nightly changed: review symbols before patching"
    assert text and text[0] == 0x100000000, "Unexpected text mapping"
    before = hashlib.sha256(data).hexdigest()
    for source, target in PATCHES.items():
        location = text[2] + source
        assert struct.unpack_from("<I", data, location)[0] == 0xD4200020, hex(source)
        instruction = 0x14000000 | (((target - source) // 4) & 0x3FFFFFF)
        struct.pack_into("<I", data, location, instruction)
    path.write_bytes(data)
    result = {"uuid": uuid.hex(), "before_sha256": before,
              "after_sha256": hashlib.sha256(data).hexdigest(),
              "patches": {hex(a): hex(b) for a, b in PATCHES.items()}}
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    patch(sys.argv[1])
