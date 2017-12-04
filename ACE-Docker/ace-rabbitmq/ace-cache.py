#!/usr/bin/env python
import json
import sys
import pika
import requests
from argparse import ArgumentParser
from json import dumps

# Our local cache of hashes. Each of the consumers checks this dictionary first
# before doing a lookup against VirusTotal to save time and API queries
cachedEntries = {}

class CachedConsumer(object):
    """A consumer that receives hashes and queries the VirusTotal api
    to find if VirusTotal has any matching hashes, and how many positive
    (malicious) results for that hash.
    """
    EXCHANGE = 'ace_exchange'
    EXCHANGE_TYPE = 'topic'

    def __init__(self, connection):
        """Create a new instance of LookupConsumer, passing in the API key to use.

        :param connection connection: A pika connection object.
        """
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
        newRoutingKey = ""
        if 'SHA256Hash' in message and message['SHA256Hash'] is not None:
            sha256hash = message['SHA256Hash'] # assign the value temporarily instead of doing a lookup each time
            if sha256hash in cachedEntries: #hash is cached
                print "Hash is cached"
                message[u"VTRecordExists"] = cachedEntries[sha256hash][u"VTRecordExists"]
                if u"VTPositives" in cachedEntries[sha256hash]:
                    message[u"VTPositives"] = cachedEntries[sha256hash][u"VTPositives"]
                enrichment,newRoutingKey = method.routing_key.split(".",1)
                self.publish_message(method, message, newRoutingKey)
            elif u'VTRecordExists' in message: #needs to be cached
                print "Adding hash to cache"
                cachedEntries[sha256hash] = {}
                cachedEntries[sha256hash][u"VTRecordExists"] = message[u"VTRecordExists"]
                if u'VTPositives' in message:
                    cachedEntries[sha256hash][u'VTPositives'] = message[u'VTPositives']
                enrichment,newRoutingKey = method.routing_key.split(".",1)
                self.publish_message(method, message, newRoutingKey)
            else: #send for lookup
                print "sending to VT"
                newRoutingKey = "lookup." + method.routing_key
                self.publish_message(method, message, newRoutingKey)
                self._connection.sleep(1)
        elif message['SHA256Hash'] is None:
            print "Hash is null"
            enrichment,newRoutingKey = method.routing_key.split(".",1)
            self.publish_message(method, message, newRoutingKey)

    def publish_message(self, method, message, routingKey):
        """Publish a message to the channel with the new routing key after enrichment.
        """
        body = json.dumps(message)
        channel = self._channel
        channel.basic_ack(delivery_tag = method.delivery_tag)
        channel.basic_publish(exchange=self.EXCHANGE, routing_key=routingKey,body=body, properties=pika.BasicProperties(delivery_mode = 2,))

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

    args = parser.parse_args()
    try:
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

    cacheConsume = CachedConsumer(connection)

    channel.basic_consume(cacheConsume.consume_message, queue='cached_hash')

    channel.start_consuming()
    
    connection.close()

if __name__ == '__main__':
    main()