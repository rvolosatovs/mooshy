#!/usr/bin/env bash
set -e

cgi=/usr/lib/cgi-bin

f=`mktemp`
curl -sLo ${f} http://archive.ubuntu.com/ubuntu/pool/main/b/bash/bash_4.3-6ubuntu1_amd64.deb && dpkg -i ${f} && rm -f ${f}

apt-get -y install apache2

sed -i 's/#\(.*Include.*cgi-bin\)/\1/' /etc/apache2/sites-enabled/000-default.conf

cd /etc/apache2/mods-enabled
ln -sf ../mods-available/cgi.load

mkdir -pv ${cgi}
cat <<EOF >${cgi}/index.cgi
#!/bin/bash
echo "Content-type: text/plain"
echo
echo "Hello, cruel world!"
EOF

chmod +x ${cgi}/index.cgi

curl --create-dirs -sLo /usr/local/bin/hhttpd https://github.com/rvolosatovs/mooshy/releases/download/${1:-"v1.2.0"}/hhttpd-linux-amd64
chmod +x /usr/local/bin/hhttpd

systemctl restart apache2

echo 0 > /proc/sys/kernel/randomize_va_space
