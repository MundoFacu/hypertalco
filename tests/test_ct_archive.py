import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from hypertalco.ct_archive import validate_archive
from hypertalco.validation import Invalid
from hypertalco.validation import create
from hypertalco.engines import reset_uploaded_identity
import os


class CTArchiveTests(unittest.TestCase):
    def archive(self, entries):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        path = Path(temp.name) / 'rootfs.tar.xz'
        with tarfile.open(path, 'w:xz') as tar:
            for name, kind, target in entries:
                item = tarfile.TarInfo(name)
                if kind == 'file':
                    data = b'data'; item.size = len(data); tar.addfile(item, io.BytesIO(data))
                else:
                    item.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE, 'device': tarfile.CHRTYPE}[kind]
                    item.linkname = target or ''
                    tar.addfile(item)
        return path

    def test_valid_archive_with_internal_files(self):
        self.assertEqual(validate_archive(self.archive([('etc/os-release', 'file', None), ('bin', 'symlink', 'usr/bin')]))['entries'], 2)

    def test_rejects_unsafe_archive_paths_and_links(self):
        for entries in [[('../escape', 'file', None)], [('/etc/evil', 'file', None)],
                        [('etc', 'symlink', '/tmp'), ('etc/evil', 'file', None)],
                        [('item', 'symlink', '/tmp'), ('item', 'file', None)],
                        [('file', 'hardlink', '../escape')], [('dev/evil', 'device', None)]]:
            with self.subTest(entries=entries), self.assertRaises(Invalid):
                validate_archive(self.archive(entries))

    def test_uploaded_ids_are_validated_before_creating_ct(self):
        import base64
        key = b'\x00\x00\x00\x0bssh-ed25519' + b'x' * 32
        options = {'engine': 'lxc', 'name': 'ct-test', 'image': 'upload-12345678-1234-1234-1234-123456789abc',
                   'ssh_keys': 'ssh-ed25519 ' + base64.b64encode(key).decode()}
        self.assertEqual(create(options)['image'], options['image'])
        options['image'] = 'upload-../../etc/passwd'
        with self.assertRaises(Invalid):
            create(options)

    def test_clone_identity_replaced_and_host_keys_removed_without_following_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'rootfs'; (root / 'etc/ssh').mkdir(parents=True)
            (root / 'var/lib/dbus').mkdir(parents=True)
            (root / 'etc/machine-id').write_text('old')
            (root / 'var/lib/dbus/machine-id').write_text('old')
            (root / 'etc/ssh/ssh_host_ed25519_key').write_text('old key')
            reset_uploaded_identity(root, os.getuid(), os.getgid())
            first = (root / 'etc/machine-id').read_text()
            self.assertEqual(len(first.strip()), 32)
            self.assertEqual(first, (root / 'var/lib/dbus/machine-id').read_text())
            self.assertFalse((root / 'etc/ssh/ssh_host_ed25519_key').exists())
            reset_uploaded_identity(root, os.getuid(), os.getgid())
            self.assertNotEqual(first, (root / 'etc/machine-id').read_text())
            outside = Path(tmp) / 'outside'; outside.mkdir()
            (root / 'etc/ssh').rmdir(); (root / 'etc/ssh').symlink_to(outside)
            with self.assertRaises(OSError):
                reset_uploaded_identity(root, os.getuid(), os.getgid())
