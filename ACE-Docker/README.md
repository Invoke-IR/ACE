# ACE-Docker
This project focuses on simplifying ACE's deployment process as much as possible.

## Goals

## Components

### ace-app
ASP.NET Core Web Application. This is the main component of the Automated Collection and Enrichment Platform. The ACE web app allows for user, credential, and computer management, as well as, script management and tasking.

### ace-mssql-linux
ACE leverages a MSSQL database on the backend to keep track of all the data it needs to do its job. 

### ace-rabbitmq


### ace-web

## Getting Started
```
sudo git clone https://github.com/Invoke-IR/ACE.git
cd ACE/ACE-Docker
docker-compose build
docker-compose up -d
```