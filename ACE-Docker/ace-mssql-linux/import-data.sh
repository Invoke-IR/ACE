/opt/mssql/bin/sqlservr &

#wait for the SQL Server to come up
sleep 90s

#run the setup script to create the DB and the schema in the DB
echo $1
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P $1 -Q "CREATE DATABASE ACEWebService"
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P $1 -d ACEWebService -i /usr/src/ace/ace.sql

while true; do
sleep 300
done