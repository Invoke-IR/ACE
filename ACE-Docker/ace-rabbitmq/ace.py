#!/usr/bin/env python
import json
import pika
import requests
import sys
import time
from argparse import ArgumentParser
from json import dumps


def main():
	def hashlookupconsumer(ch, method, properties, body):
		message = json.loads(body)
		try:
			params = {'apikey': '4394b00b49b824695bf21eb3e55b52c8cbd5e322231ec62292b45e0d4927ab92', 'resource': message['SHA256Hash']}
			headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username"}
			response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
			if response.status_code == 204:
				time.sleep(60)
				response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
			json_response = response.json()
			if json_response['response_code'] == 1:
				message[u"VTRecordExists"] = u"True"
				message[u"VTPositives"] = json_response['positives']
				print message
			else:
				message[u"VTRecordExists"] = u"False"    
		except KeyError:
			print("No hash field")
		enrichment,newRoutingKey = method.routing_key.split(".",1)
		print("Routing Key:" + newRoutingKey)
		channel.basic_ack(delivery_tag = method.delivery_tag)
		#Need to strip the front off and enrich here and error catching
		channel.basic_publish(exchange='ace_exchange',
		                  routing_key=newRoutingKey,
		                  body=body)
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
			print "Must provide command line parameters, run 'python ACE_RabbitMQ.py -h' for help"
			return
		channel = connection.channel()
	except:
		print "Issue connecting to RabbitMQ,"

	channel.exchange_declare(exchange='ace_exchange',exchange_type='topic')

	channel.queue_declare(queue='file_output')
	channel.queue_declare(queue='siem')
	channel.queue_declare(queue='pre_hash')

	channel.queue_bind(exchange='ace_exchange',
	                   queue='siem',
	                   routing_key='siem')
	channel.queue_bind(exchange='ace_exchange',
	                   queue='file_output',
	                   routing_key='file')
	channel.queue_bind(exchange='ace_exchange',
	                   queue='pre_hash',
	                   routing_key='hash.#')

	print("Waiting for messages")

	channel.basic_consume(hashlookupconsumer, queue='pre_hash')

	channel.start_consuming()

	connection.close()

if __name__ == '__main__':
	main()