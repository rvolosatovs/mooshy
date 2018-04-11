#!/usr/bin/env bash
set -e

cgi=/usr/lib/cgi-bin

f=`mktemp`
curl -sLo ${f} http://archive.ubuntu.com/ubuntu/pool/main/b/bash/bash_4.3-6ubuntu1_amd64.deb && dpkg -i ${f} && rm -f ${f}

apt-get install apache2

sed -i 's/#\(.*Include.*cgi-bin\)/\1/' /etc/apache2/sites-enabled/000-default.conf

cd /etc/apache2/mods-enabled
ln -s ../mods-available/cgi.load

mkdir -pv ${cgi}
cat <<EOF >${cgi}/${1:-"index"}.cgi
#!/bin/bash
echo "Content-type: text/plain"
echo
echo "Hello, cruel world!"
EOF

systemctl restart apache2
