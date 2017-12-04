#!/bin/sh

# Add Environment Variable to nginx.conf
sed -i -e 's/\[WEBSERVICE_IP\]/'"$WEBSERVICE_IP"'/g' /etc/nginx/nginx.conf

# Check if /etc/nginx/certs directory exits
if [ ! -d /etc/nginx/certs ]; then
    mkdir /etc/nginx/certs
fi

# Check if SSL Cert exists, if it doesn't then make it
if [ ! -f /etc/nginx/certs/server.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -subj "/C=US/ST=Washington/L=Seattle/O=web.ace/CN=local.specterops.ace" -keyout "/etc/nginx/certs/server.key" -out "/etc/nginx/certs/server.crt" 2> /dev/null
fi

# Get and output SSL Thumbprint
fingerprint=$(openssl x509 -in /etc/nginx/certs/server.crt -noout -fingerprint | sed 's/SHA1 Fingerprint=//g' |  sed 's/://g')
echo "\"Thumbprint\": \"$fingerprint\","