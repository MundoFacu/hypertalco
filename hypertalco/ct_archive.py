"""Validate container rootfs archives before any privileged use."""
from pathlib import PurePosixPath
import subprocess
import tarfile

from .validation import Invalid

MAX_EXPANDED = 64 * 1024**3
MAX_ENTRIES = 1_000_000


def validate_archive(path):
    """Reject traversal, unsafe special entries and paths passing through archive links."""
    process = None
    raw = None
    names, links, hardlinks, kinds = set(), set(), [], {}
    size = 0
    try:
        if str(path).endswith('.zst'):
            process = subprocess.Popen(['zstd', '-d', '-q', '-c', '--', str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            raw = process.stdout
        else:
            raw = open(path, 'rb')
        with tarfile.open(fileobj=raw, mode='r|*') as archive:
            count = 0
            for member in archive:
                count += 1
                if count > MAX_ENTRIES:
                    raise Invalid('Template has too many entries')
                name = member.name
                if name.startswith('/') or '\x00' in name or '..' in PurePosixPath(name).parts:
                    raise Invalid('Template has an unsafe path')
                normalized = str(PurePosixPath(name))
                if normalized == '.':
                    continue
                if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise Invalid('Template contains a special device or unsupported entry')
                if normalized in kinds and not (kinds[normalized] == 'dir' and member.isdir()):
                    raise Invalid('Template contains conflicting duplicate paths')
                kinds[normalized] = 'dir' if member.isdir() else 'other'
                if member.uid < 0 or member.gid < 0 or member.uid >= 65536 or member.gid >= 65536:
                    raise Invalid('Template has an owner outside the container UID/GID map')
                size += member.size
                if size > MAX_EXPANDED:
                    raise Invalid('Template exceeds the 64 GiB expanded limit')
                names.add(normalized)
                if member.issym():
                    links.add(normalized)
                if member.islnk():
                    target = PurePosixPath(member.linkname)
                    if target.is_absolute() or '..' in target.parts:
                        raise Invalid('Template has an unsafe hard link')
                    hardlinks.append(str(target))
        if process and process.wait(timeout=30) != 0:
            raise Invalid('Template decompression failed')
        for name in names | set(hardlinks):
            if any(str(parent) in links for parent in PurePosixPath(name).parents if str(parent) != '.'):
                raise Invalid('Template contains a path below a symbolic link')
        if any(target in links for target in hardlinks):
            raise Invalid('Template hard link targets a symbolic link')
        if not names:
            raise Invalid('Template archive is empty')
        return {'entries': count, 'expanded_bytes': size}
    except (tarfile.TarError, EOFError, OSError) as error:
        raise Invalid('Invalid container template archive') from error
    finally:
        if raw:
            raw.close()
        if process and process.poll() is None:
            process.kill(); process.wait()
