# core/listener.py

import pika
import json
from core.utils import get_rabbitmq_connection

def callback(ch, method, properties, body):
    message = json.loads(body)
    event_type = message['eventType']
    data = message['data']
    
    print(f"Received event: {event_type}")
    print(f"Data: {data}")

    # Process the message here
    if event_type == 'user_created':
        handle_user_created(data)
    elif event_type == 'role_created':
        handle_role_created(data)
    elif event_type == 'user_logged_out':
        handle_user_logged_out(data)

def handle_user_created(data):
    print(f"Handling user created event: {data}")
    # Implement your handling logic here

def handle_role_created(data):
    print(f"Handling role created event: {data}")
    # Implement your handling logic here

def handle_user_logged_out(data):
    print(f"Handling user logged out event: {data}")
    # Implement your handling logic here

def start_listener():
    """
    Initializes a RabbitMQ listener to consume messages from the 'CRM_EVENTS_EXCHANGE' fanout exchange.

    - Establishes a connection to RabbitMQ.
    - Declares a fanout exchange ('CRM_EVENTS_EXCHANGE') to broadcast messages to all queues.
    - Declares an exclusive, temporary queue and binds it to the exchange.
    - Waits for incoming messages and processes them using the specified callback function.
    - Starts consuming messages from the bound queue until manually stopped.

    Usage:
    Call this function to listen for messages broadcast on the 'CRM_EVENTS_EXCHANGE'.
    """
    connection = get_rabbitmq_connection()
    channel = connection.channel()
    
    # Declare the fanout exchange
    channel.exchange_declare(exchange='CRM_EVENTS_EXCHANGE', exchange_type='fanout')
    
    # Declare a queue and bind it to the exchange
    result = channel.queue_declare(queue='', exclusive=True)
    queue_name = result.method.queue
    channel.queue_bind(exchange='CRM_EVENTS_EXCHANGE', queue=queue_name)
    
    print('Waiting for messages. To exit press CTRL+C')

    # Set up the consumer
    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)
    
    # Start consuming
    channel.start_consuming()