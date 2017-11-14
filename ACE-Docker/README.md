# ACE-Docker
ACE-Docker

## Components
### ace-app
ASP.NET Core Web Application. 

This is the main component of the Automated Collection and Enrichment Platform. The ACE web app allows for user, credential, and computer management, as well as, script management and tasking.

### ace-mssql-linux
MSSQL Server. 

This database provides a backend to keep track of all of the data ACE needs to do its job. This includes User, Credential, Computer, Script, and Schedules.

### ace-rabbitmq
RabbitMQ Messaging System. 

ACE's enrichment pipeline is built on a robust messaging system that guides each scan result through data enrichments, like Virus Total hash lookups, all the way to ingestion into a SIEM.

### ace-web
NGINX HTTP(S) Reverse Proxy. 

Proxy's access to the ACE Web Application and provides SSL Certificates for those connections.

## Getting Started
Our goal is to make provisioning ACE as simple as possible, so we wrote a small batch script to get things set up. Follow the steps, on a Linux or OSX machine, below and you should be in business:
* Install Docker
* If on Linux, Install Docker Compose
* Adjust Docker preferences to allow containers to use 4GBs of RAM (Docker -> Preferences -> Advanced -> Memory)
* Download this repository
* Execute start.sh

### Installing Docker
#### Linux
#### OSX
#### Windows

### Provisioning Docker Containers
start.sh is a simple shell script that accomplishes the remaining set up steps. Below is a list of tasks accomplished by start.sh:
* Create SSL certificate
* Add SSL Thumbprint to the ACE Web Application's appsettings.json file
* Generates API Key for default Admin user
* Build ACE Docker images
* Start ACE Docker containers
* Output configuration details
```
==========================================================
|      Thank you for provisioning ACE with Docker!!      |
==========================================================

Please use the following information to interact with ACE:
             Uri: https://10.57.106.141
          ApiKey: 9C8DC642-268D-41EA-9521-43F718119FB7
      Thumbprint: FA4608B93B017DF46D1BC6155DC4C5AF7D83EA1D

==========================================================
```