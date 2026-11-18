#!/usr/bin/env bash
# Compatibility entry point; the interactive installer has the canonical name below.
set -euo pipefail
exec bash "$(dirname -- "${BASH_SOURCE[0]}")/hypertalco-installer.sh" "$@"
