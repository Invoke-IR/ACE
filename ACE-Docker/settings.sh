clear

get_host_ip(){
    # *********** Getting Host IP ***************
    # https://github.com/Invoke-IR/ACE/blob/master/ACE-Docker/start.sh
    echo "[ACE-INSTALLATION-INFO] Obtaining current host IP.."
    unameOut="$(uname -s)"
    case "${unameOut}" in
        Linux*)     host_ip=$(ip route get 1 | awk '{print $NF;exit}');;
        Darwin*)    host_ip=$(ifconfig en0 | grep inet | grep -v inet6 | cut -d ' ' -f2);;
        *)          host_ip="UNKNOWN:${unameOut}"
    esac
}

# Write appsettings.Production.json to screen
get_appsettings_data(){
  echo ""
  echo ""
  echo "=========================================================="
  echo ""
  echo "    \"RabbitMQServer\": \"${host_ip}\""
  echo "    $(docker logs ace-rabbitmq | grep UserName)"
  echo "    $(docker logs ace-rabbitmq | grep Password)"
  echo "    $(docker logs ace-nginx | grep Thumbprint)"
  echo "    $(docker logs ace-sql | grep ApiKey)"
  echo "    \"SQLServer\": \"${host_ip}\""
  echo "    $(docker logs ace-sql | grep DefaultConnection)"
  echo ""
  echo "=========================================================="
  echo ""
  echo ""
}

get_ps_settings(){
# Provide configuration details for PowerShell Module
  echo ""
  echo ""
  echo "==============================================================="
  echo "|        Thank you for provisioning ACE with Docker!!         |"
  echo "|  Please use the following information to interact with ACE  |"
  echo "==============================================================="
  echo "" 
  echo "  \$settings = @{"
  echo "    Uri        = 'https://${host_ip}'"
  IFS='"' read -r -a array <<< "$(docker logs ace-sql | grep Api)"
  echo "    ApiKey     = '${array[3]}'"
  IFS='"' read -r -a array <<< "$(docker logs ace-nginx | grep Thumbprint)"
  echo "    Thumbprint = '${array[3]}'"
  echo "  }"
  echo ""
  echo "=============================================================="
  echo ""
  echo ""
}

get_host_ip
get_appsettings_data
get_ps_settings
