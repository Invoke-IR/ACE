# Get directory of script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR

# Create SSL Certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ace-web/server.key -out ace-web/server.crt
fingerprint=$(openssl x509 -in ace-web/server.crt -noout -fingerprint | sed 's/SHA1 Fingerprint=//g' |  sed 's/://g')

# Get IP Address
unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     ip=$(/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{print $1}') && apikey=$(cat /proc/sys/kernel/random/uuid);;
    Darwin*)    ip=$(ifconfig en0 | grep inet | grep -v inet6 | cut -d ' ' -f2) && apikey=$(uuidgen);;
    *)          ip="UNKNOWN:${unameOut}"
esac

cat ace-mssql-linux/ace.Template.sql | sed 's/\[APIKEY\]/'"$apikey"'/g' > ace-mssql-linux/ace.sql

# Add SSL Thumbprint 
cat ace-app/appsettings.Template.json | sed 's/\[SSL THUMBPRINT\]/'"$fingerprint"'/g' > ace-app/appsettings.Production.json

# Build Docker Images and Start Containers
docker-compose build
docker-compose up -d


# Provide configuration details for PowerShell Module
clear
echo ""
echo ""
echo "=========================================================="
echo "|      Thank you for provisioning ACE with Docker!!      |"
echo "=========================================================="
echo ""
echo "Please use the following information to interact with ACE:" 
echo "             Uri: https://$ip"
echo "          ApiKey: $apikey"
echo "      Thumbprint: $fingerprint"
echo ""
echo "=========================================================="
echo ""
echo ""