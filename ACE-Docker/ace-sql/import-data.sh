/opt/mssql/bin/sqlservr > /dev/null &

#wait for the SQL Server to come up
sleep 45s

# Create Unique API Key
apikey=$(cat /proc/sys/kernel/random/uuid)
startacesweep=$(cat /proc/sys/kernel/random/uuid)
downloadacefile=$(cat /proc/sys/kernel/random/uuid)
sed -i -e 's/\[APIKEY\]/'"$apikey"'/g' /usr/src/ace/ace.sql

#run the setup script to create the DB and the schema in the DB
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P $SA_PASSWORD -Q "CREATE DATABASE ACEWebService" > /dev/null
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P $SA_PASSWORD -d ACEWebService -i /usr/src/ace/ace.sql > /dev/null

echo "\"ApiKey\": \"$apikey\","
echo "\"StartAceSweep\": \"$startacesweep\","
echo "\"DownloadAceFile\": \"$downloadacefile\""
echo "\"DefaultConnection\": \"Server=sql.ace.local;Database=ACEWebService;User Id=sa;Password=$SA_PASSWORD;MultipleActiveResultSets=true\""

while true; do
sleep 300
done