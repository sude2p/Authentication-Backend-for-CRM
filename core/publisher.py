import json
import pika
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out
from .models import User
from .utils import get_rabbitmq_connection

def publish_to_rabbitmq(event_type, data):
    """
    Publishes an event to a RabbitMQ fanout exchange.

    Args:
        event_type (str): The type of event being published.
        data (dict): The data associated with the event.

    The function establishes a connection to RabbitMQ, declares a fanout 
    exchange named 'CRM_EVENTS_EXCHANGE', and publishes a JSON-encoded message 
    containing the event type and data.
    """
    # connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    connection = get_rabbitmq_connection()
    channel = connection.channel()

    # Declare a fanout exchange
    channel.exchange_declare(exchange='CRM_EVENTS_EXCHANGE', exchange_type='fanout')

    # Create a message
    message = json.dumps({
        'eventType': event_type,
        'data': data
    })
    

    # Publish message to the exchange
    channel.basic_publish(exchange='CRM_EVENTS_EXCHANGE', routing_key='', body=message)
    # connection.close()
    print("Message published")
    
    
#if we use signals
'''  
@receiver(post_save, sender=User)
def publish_user_created(sender, instance, created, **kwargs):
    if created:
        publish_to_rabbitmq('user_created', {
            'user_id': instance.id,
            'email': instance.email,
            'first_name': instance.first_name,
            'last_name': instance.last_name,
            'contact_number': instance.contact_number
        })

@receiver(user_logged_in)
def publish_user_logged_in(sender, request, user, **kwargs):
    publish_to_rabbitmq('user_logged_in', {
        'user_id': user.id,
        'email': user.email
    })

@receiver(user_logged_out)
def publish_user_logged_out(sender, request, user, **kwargs):
    publish_to_rabbitmq('user_logged_out', {
        'user_id': user.id,
        'email': user.email
    })    
    
'''
