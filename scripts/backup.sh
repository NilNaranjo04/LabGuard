#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p backups
stamp=$(date +%F_%H-%M-%S)
tar czf "backups/labguard_backup_${stamp}.tar.gz" instance .env docker-compose.yml nginx/default.conf
ls -lh backups | tail -n 5
