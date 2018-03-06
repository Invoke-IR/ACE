Built on [RabbitMQ](https://hub.docker.com/_/rabbitmq/), this images provides the backend database used by the [ACE RabbitMQ Server](https://github.com/Invoke-IR/ACE/tree/master/ACE-RabbitMQ).

## Requirements
* This image requires Docker Engine 1.8+ in any of their supported platforms.
* Requires the following environment flags
* RABBITMQ_DEFAULT_USER=<username>
* RABBITMQ_DEFAULT_PASS=<your_strong_password>
* APIKEY=<virustotal_apikey>

## Using this Image
### Run
```
docker run --name ace-rabbitmq -e 'RABBITMQ_DEFAULT_USER=yourUsername' -e 'RABBITMQ_DEFAULT_PASS=yourPassword' -e 'APIKEY=yourVirusTotalPublicAPIKey' -p 5672:5672 -p 15672:15672 -d specterops/ace-rabbitmq
```
# For Persistence
If you desire your RabbitMQ data and setting to persist between containers, you need to create a docker volume `docker volume create rabbitmq` then add `-v rabbitmq:/var/lib/rabbitmq` to the docker run command

### Environment Variables
* **RABBITMQ_DEFAULT_USER** Username for RabbitMQ server. Will be used to connect to server and log into management interface.
* **RABBITMQ_DEFAULT_PASS** Password for RabbitMQ server. Will be used to connect to server and log into management interface.
* **APIKEY** Public VirusTotal API key. Allows for lookups of hashes on VirusTotal