"""Validate actual compiler metadata in the packaged Duo host and LiveProcess."""
import hashlib
import json
import plistlib
import struct
import sys
import zipfile
from pathlib import Path


def sdk_versions(data):
    magic, = struct.unpack_from("<I", data)
    assert magic == 0xFEEDFACF, "Expected thin 64-bit Mach-O"
    count, size = struct.unpack_from("<II", data, 16)
    offset = 32
    versions = []
    for _ in range(count):
        command, length = struct.unpack_from("<II", data, offset)
        assert length >= 8 and offset + length <= 32 + size
        if command == 0x32:
            platform, minimum, sdk = struct.unpack_from("<III", data, offset + 8)
            assert platform == 2, "Expected iOS device binary"
            assert sdk >= (27 << 16 | 1 << 8), "Binary built with an older SDK"
            versions.append({"sdk": sdk, "minimum_os": minimum})
        offset += length
    assert offset == 32 + size and versions
    return versions


def validate(path):
    checks = {}
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(set(archive.namelist()))
        root = "Payload/LiveContainer.app/"
        info = plistlib.loads(archive.read(root + "Info.plist"))
        assert set(info["UIDeviceFamily"]) == {1, 2}
        assert not info.get("UIRequiresFullScreen", False)
        assert len(info["UISupportedInterfaceOrientations"]) == 4
        assert info.get("UILaunchStoryboardName")
        checks["host"] = sdk_versions(archive.read(root + info["CFBundleExecutable"]))
        process = next(n for n in archive.namelist()
                       if n.endswith("LiveProcess.appex/Info.plist"))
        extension = plistlib.loads(archive.read(process))
        assert not extension.get("UIRequiresFullScreen", False)
        checks["liveprocess"] = sdk_versions(archive.read(
            process.rsplit("/", 1)[0] + "/" + extension["CFBundleExecutable"]))
        assert root + "Frameworks/SideStoreApp.framework/SideStore" in archive.namelist()
        checks["sidestore_embedded"] = True
        checks["host_sdk_name"] = info["DTSDKName"]
        checks["xcode"] = info["DTXcode"]
    checks["message"] = "Real SDK build metadata and package checks passed; device behavior unverified."
    checks["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    checks["runtime_tested"] = False
    Path("duo-ipa-validation.json").write_text(json.dumps(checks, indent=2) + "\n")
    print(json.dumps(checks, indent=2))


if __name__ == "__main__":
    validate(Path(sys.argv[1]))
