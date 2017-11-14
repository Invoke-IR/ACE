/opt/mssql/bin/sqlservr &

#wait for the SQL Server to come up
sleep 45s

# Create Unique API Key
echo ">> Generating ACE API Key"

apikey=$(cat /proc/sys/kernel/random/uuid)
sed -i -e 's/\[APIKEY\]/'"$apikey"'/g' /usr/src/ace/ace.sql

#run the setup script to create the DB and the schema in the DB
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P $1 -Q "CREATE DATABASE ACEWebService"
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P $1 -d ACEWebService -i /usr/src/ace/ace.sql

echo ">> ########################################################"
echo ">> # ACE Admin APIKey: $apikey"
echo ">> # SQL Server SA Password: $1"
echo ">> ########################################################"

while true; do
sleep 300
done