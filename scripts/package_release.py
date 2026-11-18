#!/usr/bin/env python3
"""Build a deterministic local release. Does not publish or install anything."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parent.parent
INCLUDE = ['hypertalco', 'scripts', 'packaging', 'docs', 'tests', 'README.md',
           'LICENSE', 'VERSION',
           'hypertalco-installer.sh', 'install.sh']
EXCLUDE = {'docs/LAB-20261107.md', 'docs/BARELAB-20261118.md',
           'scripts/lab_acceptance.py', 'scripts/prepare_public.py',
           'scripts/barelab-install.py', 'scripts/barelab-snapshot.sh',
           'scripts/check_uploaded_lxc_barelab.py', 'scripts/check_ct_import_barelab.py',
           'tests/test_barelab_install.py'}


def build(destination):
    version = (ROOT / 'VERSION').read_text().strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid release version')
    prefix = 'hypertalco-' + version
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / (prefix + '.tar.gz')
    files = []
    for name in INCLUDE:
        path = ROOT / name
        files += [p for p in path.rglob('*') if p.is_file() and '__pycache__' not in p.parts] if path.is_dir() else [path]
    files = [p for p in files if str(p.relative_to(ROOT)) not in EXCLUDE]
    with archive.open('wb') as output, gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as tar:
            for path in sorted(files):
                if path.is_symlink():
                    raise ValueError('Release source must not contain symlinks')
                data = path.read_bytes()
                info = tarfile.TarInfo(prefix + '/' + str(path.relative_to(ROOT)))
                info.size, info.mtime, info.uid, info.gid = len(data), 0, 0, 0
                info.mode = 0o755 if path.suffix == '.sh' else 0o644
                tar.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = destination / (archive.name + '.sha256')
    checksum.write_text(digest + '  ' + archive.name + '\n')
    print(str(archive)); print(str(checksum))
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'output/releases')
    build(parser.parse_args().output)
