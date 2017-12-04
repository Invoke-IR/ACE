# Get directory of script and change to it
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

# Build Docker Images and Start Containers
docker-compose build
docker-compose up -d

# Get IP Address
unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     ip=$(/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{print $1}');;
    Darwin*)    ip=$(ifconfig en0 | grep inet | grep -v inet6 | cut -d ' ' -f2);;
    CYGWIN*)    ip=Cygwin;;
    MINGW*)     ip=MinGw;;
    *)          ip="UNKNOWN:${unameOut}"
esac

sleep 60

# Write appsettings.Production.json to screen
clear
echo ""
echo ""
echo "=========================================================="
echo "|              appsettings.Production.json               |"
echo "=========================================================="
echo ""
echo "{"
echo "  \"Logging\": {"
echo "    \"IncludeScopes\": false,"
echo "    \"LogLevel\": {"
echo "      \"Default\": \"Debug\","
echo "      \"System\": \"Information\","
echo "      \"Microsoft\": \"Information\""
echo "    }"
echo "  },"
echo ""
echo "  \"AppSettings\": {"
echo "    \"RabbitMQServer\": \"$ip\","
echo "    $(docker logs ace-rabbitmq | grep UserName)"
echo "    $(docker logs ace-rabbitmq | grep Password)"
echo "    $(docker logs ace-nginx | grep Thumbprint)"
echo "    $(docker logs ace-sql | grep ApiKey)"
echo "    $(docker logs ace-sql | grep StartAceSweep)"
echo "    $(docker logs ace-sql | grep DownloadAceFile)"
echo "  },"
echo ""
echo "  \"ConnectionStrings\": {"
echo "    $(docker logs ace-sql | grep DefaultConnection | sed s/sql.ace.local/$ip/)"
echo "  }"
echo "}"
echo ""
echo "=========================================================="
echo ""
echo ""

# Provide configuration details for PowerShell Module
echo "==============================================================="
echo "|        Thank you for provisioning ACE with Docker!!         |"
echo "|  Please use the following information to interact with ACE  |"
echo "==============================================================="
echo "" 
echo "  \$settings = @{"
echo "    Uri        = 'https://$ip'"
IFS='"' read -r -a array <<< "$(docker logs ace-sql | grep Api)"
echo "    ApiKey     = '${array[3]}'"
IFS='"' read -r -a array <<< "$(docker logs ace-nginx | grep Thumbprint)"
echo "    Thumbprint = '${array[3]}'"
echo "  }"
echo ""
echo "=============================================================="
echo ""
echo ""