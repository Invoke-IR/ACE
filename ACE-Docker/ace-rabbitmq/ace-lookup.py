#!/usr/bin/env python
import json
import sys
import pika
import requests
from argparse import ArgumentParser
from json import dumps

class VTConsumer(object):
    """A consumer that receives hashes and queries the VirusTotal api
    to find if VirusTotal has any matching hashes, and how many positive
    (malicious) results for that hash.
    """
    EXCHANGE = 'ace_exchange'
    EXCHANGE_TYPE = 'topic'

    def __init__(self, api_key, connection):
        """Create a new instance of VTConsumer, passing in the API key to use.

        :param str api_key: The VirusTotal API key to use.
        :param connection connection: A pika connection object.
        """
        self._apikey = api_key
        self._connection = connection
        self._channel = None

    def consume_message(self, channel, method, properties, body):
        """Consume a message from channel. This function is passed as a callback
        to basic_consume. After checking the body of the message, the consumer checks the
        cache and either publish the cached entry, or perform a lookup and add the result
        to the cache.
        """
        self._channel = channel
        message = json.loads(body) # parse the JSON results from the message
        entry = {}
        sha256hash = message['SHA256Hash']
        entry = self.lookup_hash(sha256hash)
        print entry
        if u'VTRecordExists' in entry:
            message[u"VTRecordExists"] = entry[u"VTRecordExists"]
        if u'VTPositives' in entry:
            message[u'VTPositives'] = entry[u'VTPositives']
        self.publish_message(method, message)

    def lookup_hash(self, sha256hash):
        """Perform a lookup against VirusTotal for a given hash.

        :param str vt_hash: A SHA256Hash to check against the VirusTotal API.
        """
        params = { 'apikey': self._apikey, 'resource': sha256hash }
        headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip, VirusTotal ACE Enrichment Consumer v0.1"}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        if response.status_code == 204:
            self._connection.sleep(60)
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        json_response = response.json()
        if json_response['response_code'] == 1:
            new_record = {}
            new_record[u"VTRecordExists"] = u"True"
            new_record[u"VTPositives"] = json_response['positives']
        elif json_response['response_code'] == 0:
            new_record = {}
            new_record[u"VTRecordExists"] = u"False"
        elif json_response['response_code'] == -2:
            new_record = {}
            new_record[u"VTRecordExists"] = u"False"
        return new_record

    def publish_message(self, method, message):
        """Publish a message to the channel with the new routing key after enrichment.
        """
        enrichment,newRoutingKey = method.routing_key.split(".",1)
        body = json.dumps(message)
        channel = self._channel
        channel.basic_ack(delivery_tag = method.delivery_tag)
        channel.basic_publish(exchange=self.EXCHANGE, routing_key=newRoutingKey,body=body, properties=pika.BasicProperties(delivery_mode = 2,))

def main():
    parser = ArgumentParser()
    parser.add_argument(
        '-s', '--Server', dest='rabbitmq_server', default='',
        help='[MANDATORY] RabbitMQ server hostname or IP address')
    parser.add_argument(
        '-u', '--User', dest='rabbitmq_user', default='',
        help='[OPTIONAL] RabbitMQ username')
    parser.add_argument(
        '-p', '--Password', dest='rabbitmq_password', default='',
        help='[OPTIONAL] RabbitMQ password')
    parser.add_argument(
        '-k', '--APIKey', dest='VTAPIKey', default='',
        help='[MANDATORY] VirusTotal API Key')

    args = parser.parse_args()
    try:
        if (args.VTAPIKey == ''):
            print("Must provide command line parameters, run 'python ACE_RabbitMQ.py -h' for help")
            return
        if (args.rabbitmq_password != '' and args.rabbitmq_user != ''):
            creds = pika.PlainCredentials(args.rabbitmq_user, args.rabbitmq_password)
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=args.rabbitmq_server,
                                            credentials=creds))
        elif (args.rabbitmq_server != ''):
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=args.rabbitmq_server))
        else:
            print("Must provide command line parameters, run 'python ACE_RabbitMQ.py -h' for help")
            return
        channel = connection.channel()
    except:
        print("Issue connecting to RabbitMQ,")

    channel.exchange_declare(exchange='ace_exchange',exchange_type='topic', durable=True)

    channel.queue_declare(queue='siem', durable=True)
    channel.queue_declare(queue='cached_hash', durable=True)
    channel.queue_declare(queue='lookup', durable=True)
    channel.queue_declare(queue='status', durable=True)

    channel.queue_bind(exchange='ace_exchange', queue='siem', routing_key='siem')
    channel.queue_bind(exchange='ace_exchange', queue='cached_hash', routing_key='hash.#')
    channel.queue_bind(exchange='ace_exchange', queue='lookup', routing_key='lookup.hash.#')
    channel.queue_bind(exchange='ace_exchange', queue='status', routing_key='status')
    channel.basic_qos(prefetch_count=1)


    print("Waiting for messages")

    consumer = VTConsumer(args.VTAPIKey, connection)
    channel.basic_consume(consumer.consume_message, queue='lookup')

    channel.start_consuming()

    connection.close()

if __name__ == '__main__':
    main()