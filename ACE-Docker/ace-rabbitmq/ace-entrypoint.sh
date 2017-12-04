#!/bin/bash
python /root/ace-lookup.py -s 127.0.0.1 -u $RABBITMQ_DEFAULT_USER -p $RABBITMQ_DEFAULT_PASS -k $APIKEY &
python /root/ace-cache.py -s 127.0.0.1 -u $RABBITMQ_DEFAULT_USER -p $RABBITMQ_DEFAULT_PASS &

echo "\"RabbitMQUserName\": \"$RABBITMQ_DEFAULT_USER\","
echo "\"RabbitMQPassword\": \"$RABBITMQ_DEFAULT_PASS\","

while true; do :; sleep 600; done