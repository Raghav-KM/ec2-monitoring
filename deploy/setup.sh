#!/usr/bin/env bash
# One-time setup on the EC2 machine, as the deploy user (ec2-user). Safe to run again.
#   scp deploy/procmon.service deploy/setup.sh ec2-user@<host>:/tmp/ && ssh ec2-user@<host> 'bash /tmp/setup.sh'
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

# the deploy user must be able to write the app folder (the pipeline copies procmon.py here)
sudo mkdir -p /opt/procmon
sudo chown "$USER" /opt/procmon

# login for the monitor, created once. systemd reads this file as root, the service itself cannot.
if [ ! -f /etc/procmon.env ]; then
  pass="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | cut -c1-20)"
  printf 'MONITOR_USER=admin\nMONITOR_PASS=%s\n' "$pass" | sudo tee /etc/procmon.env >/dev/null
  sudo chmod 600 /etc/procmon.env
  echo "Created /etc/procmon.env. Login: admin / $pass   (save it now; it is not shown again)"
else
  echo "/etc/procmon.env already exists, left as it is"
fi

sudo cp "$here/procmon.service" /etc/systemd/system/procmon.service
sudo systemctl daemon-reload
sudo systemctl enable procmon

echo "Done. The first run of the deploy pipeline copies procmon.py and starts the service."
