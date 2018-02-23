# Get directory of script and change to it
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

LOGFILE="/var/log/ace-install.log"
echoerror() {
    printf "${RC} * ERROR${EC}: $@\n" 1>&2;
}

install_docker(){
  unameOut="$(uname -s)"
  if [ "${unameOut}" == "Linux" ]; then
      # Reference: https://get.docker.com/
      echo "[ACE-DOCKER-INSTALLATION-INFO] ACE identified Linux as the system kernel"
      echo "[ACE-DOCKER-INSTALLATION-INFO] Checking distribution list and version"
      # *********** Check distribution list ***************
      lsb_dist="$(. /etc/os-release && echo "$ID")"
      lsb_dist="$(echo "$lsb_dist" | tr '[:upper:]' '[:lower:]')"

      # *********** Check distribution version ***************
      case "$lsb_dist" in
          ubuntu)
              if [ -x "$(command -v lsb_release)" ]; then
                  dist_version="$(lsb_release --codename | cut -f2)"
              fi
              if [ -z "$dist_version" ] && [ -r /etc/lsb-release ]; then
                  dist_version="$(. /etc/lsb-release && echo "$DISTRIB_CODENAME")"
              fi
          ;;
          debian|raspbian)
              dist_version="$(sed 's/\/.*//' /etc/debian_version | sed 's/\..*//')"
              case "$dist_version" in
                  9)
                      dist_version="stretch"
                  ;;
                  8)
                      dist_version="jessie"
                  ;;
                  7)
                      dist_version="wheezy"
                  ;;
              esac
          ;;
          centos)
              if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
                  dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
              fi
          ;;
          rhel|ol|sles)
              ee_notice "$lsb_dist"
              #exit 1
              ;;
          *)
              if [ -x "$(command -v lsb_release)"]; then
                  dist_version="$(lsb_release --release | cut -f2)"
              fi
              if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
                  dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
              fi
          ;;
      esac
      echo "[ACE-DOCKER-INSTALLATION-INFO] You're using $lsb_dist version $dist_version"            
      ERROR=$?
      if [ $ERROR -ne 0 ]; then
          echoerror "Could not verify distribution or version of the OS (Error Code: $ERROR)."
      fi

      # *********** Check if docker is installed ***************
      if [ -x "$(command -v docker)" ]; then
          echo "[ACE-DOCKER-INSTALLATION-INFO] Docker already installed"
          echo "[ACE-DOCKER-INSTALLATION-INFO] Dockerizing ACE.."
      else
          echo "[ACE-DOCKER-INSTALLATION-INFO] Docker is not installed"
          echo "[ACE-DOCKER-INSTALLATION-INFO] Checking if curl is installed first"
          if [ -x "$(command -v curl)" ]; then
              echo "[ACE-DOCKER-INSTALLATION-INFO] curl is already installed"
              echo "[ACE-DOCKER-INSTALLATION-INFO] Ready to install  Docker.."
          else
              echo "[ACE-DOCKER-INSTALLATION-INFO] curl is not installed"
              echo "[ACE-DOCKER-INSTALLATION-INFO] Installing curl before installing docker.."
              apt-get install -y curl >> $LOGFILE 2>&1
              ERROR=$?
              if [ $ERROR -ne 0 ]; then
                  echoerror "Could not install curl (Error Code: $ERROR)."
                  #exit 1
              fi
          fi
          # ****** Installing via convenience script ***********
          echo "[ACE-DOCKER-INSTALLATION-INFO] Installing docker via convenience script.."
          curl -fsSL get.docker.com -o /tmp/get-docker.sh >> $LOGFILE 2>&1
          chmod +x /tmp/get-docker.sh >> $LOGFILE 2>&1
          /tmp/get-docker.sh >> $LOGFILE 2>&1
          ERROR=$?
          if [ $ERROR -ne 0 ]; then
              echoerror "Could not install docker via convenience script (Error Code: $ERROR)."
              #exit 1
          fi
          # ****** Installing docker-compose ***********
          echo "[HELK-DOCKER-INSTALLATION-INFO] Installing docker-compose .."
          curl -L https://github.com/docker/compose/releases/download/1.19.0/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose >> $LOGFILE 2>&1
          chmod +x /usr/local/bin/docker-compose >> $LOGFILE 2>&1
          ERROR=$?
          if [ $ERROR -ne 0 ]; then
              echoerror "Could not install docker-compose (Error Code: $ERROR)."
              exit 1
          fi
      fi
  else
      # *********** Check if docker is installed ***************
      if [ -x "$(command -v docker)" ]; then
          echo "[ACE-DOCKER-INSTALLATION-INFO] Docker already installed"
          echo "[ACE-DOCKER-INSTALLATION-INFO] Dockerizing ACE.."
      else
          echo "[ACE-DOCKER-INSTALLATION-INFO] Install docker for $unameOut"
          #exit 1
      fi
  fi
}

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
    
    # *********** Accepting Defaults or Allowing user to set ACE IP ***************
    local ip_choice
    local read_input
    read -t 30 -p "[ACE-INSTALLATION-INFO] Set ACE IP. Default value is your current IP: " -e -i ${host_ip} ip_choice
    read_input=$?
    ip_choice="${ip_choice:-$host_ip}"
    if [ $ip_choice != $host_ip ]; then
        host_ip=$ip_choice
    fi
    if [ $read_input  = 142 ]; then
       echo -e "\n[ACE-INSTALLATION-INFO] ACE IP set to ${host_ip}" 
    else
    echo "[ACE-INSTALLATION-INFO] ACE IP set to ${host_ip}"
    fi
}

# Test if Docker and Docker-Compose are installed
install_docker

# Get the IP Address for later
get_host_ip

# Build Docker Images and Start Containers
echo "[ACE-INSTALLATION-INFO] Building ACE Docker Containers"
docker-compose build >> $LOGFILE 2>&1
echo "[ACE-INSTALLATION-INFO] Starting ACE Docker Images"
docker-compose up -d >> $LOGFILE 2>&1

echo "[ACE-INSTALLATION-INFO] Waiting for Docker Images to Start"
sleep 60

# Write appsettings.Production.json to screen
clear
echo ""
echo ""
echo "=========================================================="
echo ""
echo "    RabbitMQServer: ${host_ip}"
echo "    $(docker logs ace-rabbitmq | grep UserName)"
echo "    $(docker logs ace-rabbitmq | grep Password)"
echo "    $(docker logs ace-nginx | grep Thumbprint)"
echo "    $(docker logs ace-sql | grep ApiKey)"
echo "    $(docker logs ace-sql | grep StartAceSweep)"
echo "    $(docker logs ace-sql | grep DownloadAceFile)"
echo "    $(docker logs ace-sql | grep DefaultConnection)"
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