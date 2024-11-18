from django.core.management.base import BaseCommand
import threading
from core.listener import start_listener

class Command(BaseCommand):
    help = 'Start the RabbitMQ listener'

    def handle(self, *args, **kwargs):
        listener_thread = threading.Thread(target=start_listener)
        listener_thread.start()
        self.stdout.write(self.style.SUCCESS('RabbitMQ listener started'))