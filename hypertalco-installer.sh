#!/usr/bin/env bash
# Hypertalco installer. Never executes as part of the development/test workflow.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
source_dir='' repo='' version='1.0.1' check=0 upgrade=0
wizard_args=()
while (($#)); do
  case "$1" in
    --source|--repo|--version)
      (($# >= 2)) || { echo "Missing value for $1" >&2; exit 2; }
      case "$1" in --source) source_dir=$2;; --repo) repo=$2;; --version) version=$2;; esac
      shift 2;;
    --plan) check=1; wizard_args+=("$1"); shift;;
    --check) check=1; wizard_args+=("$1"); shift;;
    --upgrade) upgrade=1; wizard_args+=("$1"); shift;;
    --help) echo 'Usage: hypertalco-installer.sh [--source DIR] [--plan|--check|--upgrade]'; echo 'Default: interactive root installer. --plan only previews choices.'; exit 0;;
    *) wizard_args+=("$1"); shift;;
  esac
done
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid release version'; exit 2; }
if [[ -z $source_dir ]]; then
  here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-/dev/null}")" && pwd)
  [[ ! -f $here/hypertalco/__init__.py ]] || source_dir=$here
fi
if ((check)); then
  [[ -f $source_dir/scripts/installer.py ]] || { echo '--plan/--check needs --source DIR'; exit 2; }
  exec python3 "$source_dir/scripts/installer.py" --source "$source_dir" "${wizard_args[@]}"
fi
[[ $EUID == 0 ]] || { echo 'Installation requires root. Review the source, then run with sudo.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A systemd host is required'; exit 1; }
[[ ! -e /etc/hypertalco/config.json || $upgrade == 1 ]] || { echo 'An installation already exists. Use --upgrade explicitly.'; exit 1; }
scratch=$(mktemp -d /tmp/hypertalco-install.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
umask 077
if [[ -z $source_dir ]]; then
  [[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'Provide --repo OWNER/REPOSITORY or --source DIR'; exit 2; }
  for tool in curl python3 sha256sum; do command -v "$tool" >/dev/null || { echo "$tool is required for bootstrap"; exit 1; }; done
  archive="hypertalco-$version.tar.gz"
  base="https://github.com/$repo/releases/download/v$version"
  curl --fail --location --proto '=https' --tlsv1.2 "$base/$archive" -o "$scratch/$archive"
  curl --fail --location --proto '=https' --tlsv1.2 "$base/$archive.sha256" -o "$scratch/$archive.sha256"
  (cd "$scratch" && sha256sum --check --strict "$archive.sha256")
  python3 - "$scratch/$archive" "$scratch/source" <<'PY'
import pathlib,shutil,sys,tarfile
out=pathlib.Path(sys.argv[2]);out.mkdir()
with tarfile.open(sys.argv[1]) as tar:
    for member in tar.getmembers():
        p=pathlib.PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or not (member.isfile() or member.isdir()):
            raise SystemExit('Unsafe release archive member')
        target=out.joinpath(*p.parts)
        if member.isdir():target.mkdir(parents=True,exist_ok=True)
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            with tar.extractfile(member) as src,target.open('xb') as dst:shutil.copyfileobj(src,dst)
            target.chmod(0o755 if member.mode&0o111 else 0o644)
PY
  source_dir="$scratch/source/hypertalco-$version"
fi
[[ -f $source_dir/hypertalco/web.py && -f $source_dir/scripts/host_setup.py ]] || { echo 'Incomplete source tree'; exit 1; }
source_dir=$(realpath -- "$source_dir")
python3 "$source_dir/scripts/installer.py" --source "$source_dir" "${wizard_args[@]}"
