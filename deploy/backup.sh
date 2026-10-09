#!/bin/sh
# Consistent-enough backup of the data directory (users, messages, receipts). Run from cron, e.g. hourly.
# Usage: backup.sh /var/lib/chat /backups
set -eu
src="${1:?data dir}"; dst="${2:?backup dir}"
mkdir -p "$dst"
umask 077
tar -czf "$dst/chat-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$src" .
# keep the newest 48
ls -1t "$dst"/chat-*.tar.gz | tail -n +49 | xargs -r rm --
