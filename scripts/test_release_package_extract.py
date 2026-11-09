import io
import json
from pathlib import Path
import stat
import tarfile
from tempfile import TemporaryDirectory
import unittest
import zipfile

import artifact_install as release
from pilot import SafeError


def package_tar(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, content, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = content
                archive.addfile(info)
            else:
                data = content if isinstance(content, bytes) else content.encode()
                info.size = len(data)
                info.mode = 0o755 if name.endswith("/cli.js") else 0o644
                archive.addfile(info, io.BytesIO(data))
    stream.seek(0)
    return stream


def grafana_wheel(path, binary=b"synthetic executable", *, symlink=False, unsafe=False):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("mcp_grafana-2.0.2.dist-info/METADATA", "Name: mcp-grafana\nVersion: 2.0.2\n")
        info = zipfile.ZipInfo("mcp_grafana/bin/mcp-grafana")
        info.external_attr = (stat.S_IFLNK | 0o777 if symlink else stat.S_IFREG | 0o755) << 16
        archive.writestr(info, "../../outside" if symlink else binary)
        if unsafe:
            archive.writestr("../../outside", b"bad")


class ReleasePackageExtractionTests(unittest.TestCase):
    def test_extracts_only_a_matching_npm_package_without_running_lifecycle_scripts(self):
        payload = package_tar([
            ("package/package.json", json.dumps({"name": "demo", "version": "1.2.3", "scripts": {"install": "touch marker"}}), "file"),
            ("package/dist/cli.js", "#!/usr/bin/env node\nprocess.exit(0)\n", "file"),
        ])
        with TemporaryDirectory() as temporary:
            archive = Path(temporary) / "package.tgz"
            archive.write_bytes(payload.read())
            destination = Path(temporary) / "node_modules/demo"
            release.extract_npm_package(archive, destination, name="demo", version="1.2.3")
            self.assertEqual(json.loads((destination / "package.json").read_text())["name"], "demo")
            self.assertEqual((destination / "dist/cli.js").stat().st_mode & 0o777, 0o755)
            self.assertFalse((Path(temporary) / "marker").exists())

    def test_rejects_path_traversal_and_links(self):
        for entries in (
            [("package/package.json", json.dumps({"name": "demo", "version": "1.2.3"}), "file"),
             ("package/../../escape", "bad", "file")],
            [("package/package.json", json.dumps({"name": "demo", "version": "1.2.3"}), "file"),
             ("package/link", "../../outside", "symlink")],
        ):
            with self.subTest(entries=entries):
                payload = package_tar(entries)
                with TemporaryDirectory() as temporary:
                    archive = Path(temporary) / "package.tgz"
                    archive.write_bytes(payload.read())
                    with self.assertRaises(SafeError):
                        release.extract_npm_package(archive, Path(temporary) / "tree/demo", name="demo", version="1.2.3")

    def test_platform_filter_keeps_only_matching_constraints(self):
        self.assertTrue(release.platform_installable({"os": ["darwin"], "cpu": ["arm64"]}, "darwin", "arm64"))
        self.assertFalse(release.platform_installable({"os": ["linux"], "cpu": ["arm64"]}, "darwin", "arm64"))
        self.assertFalse(release.platform_installable({"os": ["darwin"], "cpu": ["x64"]}, "darwin", "arm64"))
        self.assertTrue(release.platform_installable({"os": ["!win32"]}, "darwin", "arm64"))
        self.assertFalse(release.platform_installable({"os": ["!darwin"]}, "darwin", "arm64"))

    def test_extracts_only_the_pinned_grafana_executable_from_wheel(self):
        binary = b"synthetic reviewed executable"
        with TemporaryDirectory() as temporary:
            wheel = Path(temporary) / "mcp_grafana-2.0.2.whl"
            target = Path(temporary) / "bin/mcp-grafana"
            grafana_wheel(wheel, binary)
            digest = __import__("hashlib").sha256(binary).hexdigest()
            release.extract_grafana_executable(wheel, target, expected_sha256=digest)
            self.assertEqual(target.read_bytes(), binary)
            self.assertTrue(target.stat().st_mode & 0o111)

    def test_grafana_wheel_extraction_rejects_links_and_unsafe_names(self):
        for options in ({"symlink": True}, {"unsafe": True}):
            with self.subTest(options=options), TemporaryDirectory() as temporary:
                wheel = Path(temporary) / "mcp_grafana-2.0.2.whl"
                target = Path(temporary) / "bin/mcp-grafana"
                grafana_wheel(wheel, **options)
                with self.assertRaises(SafeError):
                    release.extract_grafana_executable(wheel, target, expected_sha256="0" * 64)

    def test_extracts_only_a_versioned_python_runtime_without_following_links(self):
        import unittest.mock

        def archive_bytes(*, version="3.13.12", symlink=False, unsafe=False):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                for name, data in (
                    ("python/bin/python3.13", b"synthetic python executable"),
                    ("python/include/python3.13/patchlevel.h", f'#define PY_VERSION "{version}"\n'.encode()),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o755 if name.endswith("python3.13") else 0o644
                    archive.addfile(info, io.BytesIO(data))
                if symlink:
                    info = tarfile.TarInfo("python/bin/python")
                    info.type = tarfile.SYMTYPE
                    info.linkname = "../../outside"
                    archive.addfile(info)
                if unsafe:
                    info = tarfile.TarInfo("python/../../outside")
                    info.size = 1
                    archive.addfile(info, io.BytesIO(b"x"))
            stream.seek(0)
            return stream.read()

        for options, reason in (({"symlink": True}, "RUNTIME_ARCHIVE_LINK_INVALID"),
                                ({"unsafe": True}, "PACKAGE_ARCHIVE_PATH_INVALID"),
                                ({"version": "3.14.5"}, "RUNTIME_VERSION_MISMATCH")):
            with self.subTest(options=options), TemporaryDirectory() as temporary:
                archive = Path(temporary) / "runtime.tar.gz"
                destination = Path(temporary) / "runtime/python"
                archive.write_bytes(archive_bytes(**options))
                with unittest.mock.patch.object(release, "inspect_grafana_native", return_value={"architectures": ["arm64"]}):
                    with self.assertRaises(SafeError) as caught:
                        release.extract_python_runtime_archive(archive, destination, version="3.13.12")
                self.assertEqual(str(caught.exception), reason)

        with TemporaryDirectory() as temporary:
            archive = Path(temporary) / "runtime.tar.gz"
            destination = Path(temporary) / "runtime/python"
            archive.write_bytes(archive_bytes())
            with unittest.mock.patch.object(release, "inspect_grafana_native", return_value={"architectures": ["arm64"]}):
                result = release.extract_python_runtime_archive(archive, destination, version="3.13.12")
            self.assertEqual((result / "include/python3.13/patchlevel.h").read_text(), '#define PY_VERSION "3.13.12"\n')

    def test_extracts_python_wheel_and_rejects_unsafe_or_unhandled_scheme(self):
        def wheel_bytes(*, unsafe=False, data_scheme=False):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("demo-1.2.3.dist-info/METADATA", "Name: demo\nVersion: 1.2.3\n")
                archive.writestr("demo/__init__.py", "value = 1\n")
                if unsafe:
                    archive.writestr("../escape.py", "bad\n")
                if data_scheme:
                    archive.writestr("demo-1.2.3.data/scripts/demo", "#!/bin/sh\n")
            stream.seek(0)
            return stream.read()

        with TemporaryDirectory() as temporary:
            wheel = Path(temporary) / "demo-1.2.3-py3-none-any.whl"
            destination = Path(temporary) / "site-packages"
            wheel.write_bytes(wheel_bytes())
            release.extract_python_wheel(wheel, destination, name="demo", version="1.2.3")
            self.assertEqual((destination / "demo/__init__.py").read_text(), "value = 1\n")

        for options, reason in (({"unsafe": True}, "WHEEL_PATH_INVALID"),
                                ({"data_scheme": True}, "WHEEL_SCHEME_UNSUPPORTED")):
            with self.subTest(options=options), TemporaryDirectory() as temporary:
                wheel = Path(temporary) / "demo-1.2.3-py3-none-any.whl"
                wheel.write_bytes(wheel_bytes(**options))
                with self.assertRaises(SafeError) as caught:
                    release.extract_python_wheel(wheel, Path(temporary) / "site-packages", name="demo", version="1.2.3")
                self.assertEqual(str(caught.exception), reason)


if __name__ == "__main__":
    unittest.main()
