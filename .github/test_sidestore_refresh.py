"""Execute the actual ARM64 ASN.1 helper against invalid and valid lengths.

Requires Unicorn on the test host only. Foundation Data accessors are stubbed;
the parser's instruction stream, branches, stack and optional return are real.
"""
import importlib.util
from pathlib import Path
import random
import struct
import tempfile
import zipfile
import sys

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm64_const import *

spec = importlib.util.spec_from_file_location("patcher", Path(__file__).with_name("patch_sidestore_refresh.py"))
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)


def execute(binary, value):
    base, stack, heap, stop = 0x100000000, 0x200000000, 0x300000000, 0x400000000
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    cpu.mem_map(base, 0x2000000)
    cpu.mem_write(base, binary)
    cpu.mem_map(stack, 0x10000)
    cpu.mem_map(heap, 0x10000)
    cpu.mem_map(stop, 0x1000)
    cpu.mem_write(heap, value)
    cpu.mem_write(base + 0x114D800, struct.pack('<Q', heap + 0xF000))
    cpu.reg_write(UC_ARM64_REG_SP, stack + 0xF000)
    cpu.reg_write(UC_ARM64_REG_LR, stop)
    cpu.reg_write(UC_ARM64_REG_X0, len(value) << 32)
    cpu.reg_write(UC_ARM64_REG_X1, 0x4000000000000000 | heap)
    cpu.reg_write(UC_ARM64_REG_X2, 0)
    slices = []

    def hook(cpu, address, size, _):
        offset = address - base
        if offset == 0xDC4DD0:  # Data subscript getter
            index = cpu.reg_read(UC_ARM64_REG_X0)
            assert index < len(value)
            cpu.reg_write(UC_ARM64_REG_X0, value[index])
        elif offset == 0xDC480C:  # __DataStorage._bytes
            cpu.reg_write(UC_ARM64_REG_X0, heap)
        elif offset == 0xDC4830:  # __DataStorage._offset
            cpu.reg_write(UC_ARM64_REG_X0, 0)
        elif offset == 0xDC4E78:  # Data.subdata(in:)
            start, end = cpu.reg_read(UC_ARM64_REG_X0), cpu.reg_read(UC_ARM64_REG_X1)
            assert 0 <= start <= end <= len(value), (start, end)
            slices.append(value[start:end])
            cpu.reg_write(UC_ARM64_REG_X0, 0x1234)
            cpu.reg_write(UC_ARM64_REG_X1, 0x4000000000000000 | heap)
        else:
            return
        cpu.reg_write(UC_ARM64_REG_PC, cpu.reg_read(UC_ARM64_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, hook)
    cpu.emu_start(base + 0x7150B8, stop, count=100000)
    assert cpu.reg_read(UC_ARM64_REG_PC) == stop, 'Parser did not return'
    return slices, cpu.reg_read(UC_ARM64_REG_X2)


def main(ipa):
    if zipfile.is_zipfile(ipa):
        with zipfile.ZipFile(ipa) as archive:
            original = archive.read('Payload/LiveContainer.app/Frameworks/SideStoreApp.framework/SideStore')
    else:
        original = Path(ipa).read_bytes()
    # Negative wrapped length and positive signed-add overflow, both from bogus
    # plaintext during password probing. The old binary must reproduce a trap.
    failures = [bytes.fromhex('3088ffffffffffffffff') + bytes(200),
                bytes.fromhex('30887fffffffffffffff') + bytes(200)]
    for value in failures:
        try:
            execute(original, value)
        except UcError:
            pass
        else:
            raise AssertionError('Original binary did not reproduce parser trap')
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'SideStore'
        path.write_bytes(original)
        patcher.patch(path)
        patched = path.read_bytes()
    for value in failures:
        slices, optional = execute(patched, value)
        assert not slices and optional == 0xF000000000000000
    valid = [b'\x30\x03abc', b'\x04\x00', b'\x30\x81\x80' + bytes(range(128)),
             b'\x30\x82\x01\x00' + bytes(range(256))]
    for value in valid:
        assert execute(original, value) == execute(patched, value)
    rng = random.Random(27)
    for _ in range(200):
        value = bytes([0x30, rng.randrange(256)]) + rng.randbytes(256)
        try:
            expected = execute(original, value)
        except UcError:
            expected = ([], 0xF000000000000000)
        assert execute(patched, value) == expected
    print('PASS: reproduced both original traps; patched rejects safely; 4 valid and 200 malformed cases passed')


if __name__ == '__main__':
    main(sys.argv[1])
