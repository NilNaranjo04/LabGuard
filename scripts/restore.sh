#!/bin/bash
set -euo pipefail
if [ $# -ne 1 ]; then
  echo "Uso: $0 backups/nombre_del_backup.tar.gz"
  exit 1
fi
cd "$(dirname "$0")/.."
tar xzf "$1"
echo "Restauración completada."
