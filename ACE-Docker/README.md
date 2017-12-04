# ACE-Docker
This project focuses on simplifying ACE's deployment process as much as possible.

## Goals

## Components

### [specterops/ace-mssql-linux](https://hub.docker.com/r/specterops/ace-mssql-linux/)
MSSQL Server. This database provides a backend to keep track of all of the data ACE needs to do its job. This includes User, Credential, Computer, Script, and Schedules.

### [specterops/ace-rabbitmq](https://hub.docker.com/r/specterops/ace-rabbitmq/)
RabbitMQ Messaging System. ACE's enrichment pipeline is built on a robust messaging system that guides each scan result through data enrichments, like Virus Total hash lookups, all the way to ingestion into a SIEM.

### [specterops/ace-nginx](https://hub.docker.com/r/specterops/ace-nginx/)
NGINX HTTP(S) Reverse Proxy. Proxy's access to the ACE Web Application and provides SSL Certificates for those connections.

## Getting Started
Our goal is to make provisioning ACE as simple as possible, so we wrote a small batch script to get things set up. Follow the steps, on a Linux or OSX machine, below and you should be in business:
* Install Docker
* If on Linux, Install Docker Compose
* Adjust Docker preferences to allow containers to use 4GBs of RAM (Docker -> Preferences -> Advanced -> Memory)
* Download this repository
* Execute start.sh

start.sh is a simple shell script that accomplishes the remaining set up steps. Below is a list of tasks accomplished by start.sh:
* Create SSL certificate
* Add SSL Thumbprint to the ACE Web Application's appsettings.json file
* Build ACE Docker images with Docker Compose
* Start ACE Docker containers