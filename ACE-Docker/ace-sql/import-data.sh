/opt/mssql/bin/sqlservr > /dev/null &

#wait for the SQL Server to come up
sleep 45s


# Check if the database already exists
apikey="$(/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P $SA_PASSWORD -d ACEWebService -Q "SELECT ApiKey FROM dbo.Users WHERE Id='334D89C9-DA7A-43E8-A648-5DC8B22019ED'" | grep -E '[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}')"

ERROR=$?
if [ $ERROR -ne 0 ]; then
  # Create Unique API Key
  apikey=$(cat /proc/sys/kernel/random/uuid)
  sed -i -e 's/\[APIKEY\]/'"$apikey"'/g' /usr/src/ace/ace.sql

  #run the setup script to create the DB and the schema in the DB
  /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P $SA_PASSWORD -Q "CREATE DATABASE ACEWebService" > /dev/null
  /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P $SA_PASSWORD -d ACEWebService -i /usr/src/ace/ace.sql > /dev/null
fi

echo "\"ApiKey\": \"$apikey\","
echo "\"SQLPassword\": \"$SA_PASSWORD\""
#echo "\"DefaultConnection\": \"Server=sql.ace.local;Database=ACEWebService;User Id=sa;Password=$SA_PASSWORD;MultipleActiveResultSets=true\""

while true; do
sleep 300
done