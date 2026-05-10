#!/bin/bash
set -e

mkdir -p /victim-logs
touch /victim-logs/auth.log
chmod 666 /victim-logs/auth.log

# rsyslog ishga tushirish
service rsyslog start || rsyslogd -n &
sleep 1

# SSH server ishga tushirish
/usr/sbin/sshd

# Apache (HTTP target uchun)
service apache2 start || true

# Flask log API
python3 /log_api.py &

echo "[victim] Barcha xizmatlar ishga tushdi"
echo "[victim] SSH: port 22 | HTTP: port 80 | Log API: port 5000"

# Tirik turish uchun logni kuzatib turadi
tail -F /victim-logs/auth.log
