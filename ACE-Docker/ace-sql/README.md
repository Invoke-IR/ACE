Built on [microsoft/mssql-server-linux](https://hub.docker.com/r/microsoft/mssql-server-linux/), this images provides the backend database used by the [ACE Web Application](https://github.com/Invoke-IR/ACE/tree/master/ACE-WebService).
 
## Requirements
* This image requires Docker Engine 1.8+ in any of their supported platforms.
* At least 3.25 GB of RAM. Make sure to assign enough memory to the Docker VM if you're running on Docker for Mac or Windows.
* Requires the following environment flags
* SA_PASSWORD=<your_strong_password>
* A strong system administrator (SA) password: At least 8 characters including uppercase, lowercase letters, base-10 digits and/or non-alphanumeric symbols.

## Using this Image
### Run
```
docker run --name ace-sql -e 'SA_PASSWORD=yourStrong(!)Password' -e 'MSSQL_PID=Standard' -p 1433:1433 -d specterops/ace-sql
```
### For Persistence
If you desire your RabbitMQ data and setting to persist between containers, you need to create a docker volume `docker volume create sql-data` then add `-v sql-data:/var/opt/mssql` to the docker run command

### Environment Variables
* **SA_PASSWORD** is the database system administrator (userid = 'sa') password used to connect to SQL Server once the container is running. Important note: This password needs to include at least 8 characters of at least three of these four categories: uppercase letters, lowercase letters, numbers and non-alphanumeric symbols.