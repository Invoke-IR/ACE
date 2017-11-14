#!/usr/bin/env python
import json
import pika
import requests
import sys
from argparse import ArgumentParser
from json import dumps

#global hashDict

hashDict = {}

def main():
	def hashlookupconsumerRobby(ch, method, properties, body):
		message = json.loads(body)
		if 'SHA256Hash' in message and message['SHA256Hash'] != None:
			if not (message['SHA256Hash'] in hashDict):
				try:
					params = {'apikey': '', 'resource': message['SHA256Hash']}
					headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username"}
					response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					if response.status_code == 204:
						connection.sleep(60)
						response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					json_response = response.json()
					hashDict[message['SHA256Hash']] = {}
					if json_response['response_code'] == 1:
						hashDict[message['SHA256Hash']][u"VTRecordExists"] = u"True"
						hashDict[message['SHA256Hash']][u"VTPositives"] = json_response['positives']
					elif json_response['response_code'] == 0:
						hashDict[message['SHA256Hash']][u"VTRecordExists"] = u"False"
					message[u"VTRecordExists"] = hashDict[message['SHA256Hash']][u"VTRecordExists"]
					if message[u"VTRecordExists"] == u"True":
						message[u"VTPositives"] = hashDict[message['SHA256Hash']][u"VTPositives"]
				except KeyError:
					print "No hash field"
			elif message['SHA256Hash'] in hashDict:
				message[u"VTRecordExists"] = hashDict[message['SHA256Hash']][u"VTRecordExists"]
				if message[u"VTRecordExists"] == u"True":
					message[u"VTPositives"] = hashDict[message['SHA256Hash']][u"VTPositives"]
		enrichment,newRoutingKey = method.routing_key.split(".",1)
		body = json.dumps(message)
		channel.basic_ack(delivery_tag = method.delivery_tag)
		channel.basic_publish(exchange='ace_exchange',
		                  routing_key=newRoutingKey,
		                  body=body)
	def hashlookupconsumerRobby2(ch, method, properties, body):
		message = json.loads(body)
		if 'SHA256Hash' in message and message['SHA256Hash'] != None:
			if not (message['SHA256Hash'] in hashDict):
				try:
					params = {'apikey': '', 'resource': message['SHA256Hash']}
					headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username"}
					response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					if response.status_code == 204:
						connection.sleep(60)
						response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					json_response = response.json()
					hashDict[message['SHA256Hash']] = {}
					if json_response['response_code'] == 1:
						hashDict[message['SHA256Hash']][u"VTRecordExists"] = u"True"
						hashDict[message['SHA256Hash']][u"VTPositives"] = json_response['positives']
					elif json_response['response_code'] == 0:
						hashDict[message['SHA256Hash']][u"VTRecordExists"] = u"False"
					message[u"VTRecordExists"] = hashDict[message['SHA256Hash']][u"VTRecordExists"]
					if message[u"VTRecordExists"] == u"True":
						message[u"VTPositives"] = hashDict[message['SHA256Hash']][u"VTPositives"]
				except KeyError:
					print "No hash field"
			elif message['SHA256Hash'] in hashDict:
				message[u"VTRecordExists"] = hashDict[message['SHA256Hash']][u"VTRecordExists"]
				if message[u"VTRecordExists"] == u"True":
					message[u"VTPositives"] = hashDict[message['SHA256Hash']][u"VTPositives"]
		enrichment,newRoutingKey = method.routing_key.split(".",1)
		body = json.dumps(message)
		channel.basic_ack(delivery_tag = method.delivery_tag)
		channel.basic_publish(exchange='ace_exchange',
		                  routing_key=newRoutingKey,
		                  body=body)
	def hashlookupconsumerBrian(ch, method, properties, body):
		message = json.loads(body)
		if 'SHA256Hash' in message and message['SHA256Hash'] != None:
			if not (message['SHA256Hash'] in hashDict):
				try:
					params = {'apikey': '', 'resource': message['SHA256Hash']}
					headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username"}
					response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					if response.status_code == 204:
						connection.sleep(60)
						response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					json_response = response.json()
					hashDict[message['SHA256Hash']] = {}
					if json_response['response_code'] == 1:
						hashDict[message['SHA256Hash']][u"VTRecordExists"] = u"True"
						hashDict[message['SHA256Hash']][u"VTPositives"] = json_response['positives']
					elif json_response['response_code'] == 0:
						hashDict[message['SHA256Hash']][u"VTRecordExists"] = u"False"
					message[u"VTRecordExists"] = hashDict[message['SHA256Hash']][u"VTRecordExists"]
					if message[u"VTRecordExists"] == u"True":
						message[u"VTPositives"] = hashDict[message['SHA256Hash']][u"VTPositives"]
				except KeyError:
					print "No hash field"
			elif message['SHA256Hash'] in hashDict:
				message[u"VTRecordExists"] = hashDict[message['SHA256Hash']][u"VTRecordExists"]
				if message[u"VTRecordExists"] == u"True":
					message[u"VTPositives"] = hashDict[message['SHA256Hash']][u"VTPositives"]
		enrichment,newRoutingKey = method.routing_key.split(".",1)
		body = json.dumps(message)
		channel.basic_ack(delivery_tag = method.delivery_tag)
		channel.basic_publish(exchange='ace_exchange',
		                  routing_key=newRoutingKey,
		                  body=body)
	def hashlookupconsumerJared(ch, method, properties, body):
		message = json.loads(body)
		if 'SHA256Hash' in message and message['SHA256Hash'] != None:
			if not (message['SHA256Hash'] in hashDict):
				try:
					params = {'apikey': '', 'resource': message['SHA256Hash']}
					headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username"}
					response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					if response.status_code == 204:
						connection.sleep(60)
						response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					json_response = response.json()
					hashDict[message['SHA256Hash']] = {}
					if json_response['response_code'] == 1:
						hashDict[message['SHA256Hash']][u"VTRecordExists"] = u"True"
						hashDict[message['SHA256Hash']][u"VTPositives"] = json_response['positives']
					elif json_response['response_code'] == 0:
						hashDict[message['SHA256Hash']][u"VTRecordExists"] = u"False"
					message[u"VTRecordExists"] = hashDict[message['SHA256Hash']][u"VTRecordExists"]
					if message[u"VTRecordExists"] == u"True":
						message[u"VTPositives"] = hashDict[message['SHA256Hash']][u"VTPositives"]
				except KeyError:
					print "No hash field"
			elif message['SHA256Hash'] in hashDict:
				message[u"VTRecordExists"] = hashDict[message['SHA256Hash']][u"VTRecordExists"]
				if message[u"VTRecordExists"] == u"True":
					message[u"VTPositives"] = hashDict[message['SHA256Hash']][u"VTPositives"]
		enrichment,newRoutingKey = method.routing_key.split(".",1)
		body = json.dumps(message)
		channel.basic_ack(delivery_tag = method.delivery_tag)
		channel.basic_publish(exchange='ace_exchange',
		                  routing_key=newRoutingKey,
		                  body=body)
	def hashlookupconsumerJared2(ch, method, properties, body):
		message = json.loads(body)
		if 'SHA256Hash' in message and message['SHA256Hash'] != None:
			if not (message['SHA256Hash'] in hashDict):
				try:
					params = {'apikey': '', 'resource': message['SHA256Hash']}
					headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username"}
					response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					if response.status_code == 204:
						connection.sleep(60)
						response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					json_response = response.json()
					hashDict[message['SHA256Hash']] = {}
					if json_response['response_code'] == 1:
						hashDict[message['SHA256Hash']][u"VTRecordExists"] = u"True"
						hashDict[message['SHA256Hash']][u"VTPositives"] = json_response['positives']
					elif json_response['response_code'] == 0:
						hashDict[message['SHA256Hash']][u"VTRecordExists"] = u"False"
					message[u"VTRecordExists"] = hashDict[message['SHA256Hash']][u"VTRecordExists"]
					if message[u"VTRecordExists"] == u"True":
						message[u"VTPositives"] = hashDict[message['SHA256Hash']][u"VTPositives"]
				except KeyError:
					print "No hash field"
			elif message['SHA256Hash'] in hashDict:
				message[u"VTRecordExists"] = hashDict[message['SHA256Hash']][u"VTRecordExists"]
				if message[u"VTRecordExists"] == u"True":
					message[u"VTPositives"] = hashDict[message['SHA256Hash']][u"VTPositives"]
		enrichment,newRoutingKey = method.routing_key.split(".",1)
		body = json.dumps(message)
		channel.basic_ack(delivery_tag = method.delivery_tag)
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
	channel.basic_qos(prefetch_count=1)

	print("Waiting for messages")

	channel.basic_consume(hashlookupconsumerRobby, queue='pre_hash')
	channel.basic_consume(hashlookupconsumerRobby2, queue='pre_hash')
	channel.basic_consume(hashlookupconsumerBrian, queue='pre_hash')
	channel.basic_consume(hashlookupconsumerJared, queue='pre_hash')
	channel.basic_consume(hashlookupconsumerJared2, queue='pre_hash')

	channel.start_consuming()

	connection.close()

if __name__ == '__main__':
	main()