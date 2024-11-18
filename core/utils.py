from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from django.core.mail import EmailMessage
import os
import pika

from django.conf import settings
from urllib.parse import urlparse
from enum import Enum


class UserType(Enum):
    """
    Enumeration for different types of users in the system.

    Attributes:
        ADMIN (str): Represents a platform user, typically an administrator.
        USER (str): Represents an organizational user.
    """

    ADMIN = "platform_user"
    USER = "org_user"


def decode_jwt_token(token):
    """
    Decodes a JWT token to extract the user ID.

    Args:
        token (str): The JWT token to decode.

    Returns:
        int or dict: The user ID extracted from the token if valid,
                     otherwise a dictionary with an error message.
    """

    try:
        access_token = AccessToken(token)
        user_id = access_token["user_id"]
        return user_id
    except TokenError as e:
        return {"error": str(e)}


class Util:

    @staticmethod
    def send_email(data):
        """
        Sends an email using the provided data.

        Args:
            data (dict): A dictionary containing the email details. Must include:
                - 'subject' (str): The subject of the email.
                - 'body' (str): The body of the email.
                - 'to_email' (str): The recipient's email address.

        Raises:
            ValueError: If any required field is missing or invalid.
        """
        email = EmailMessage(
            subject=data["subject"],
            body=data["body"],
            from_email=settings.EMAIL_HOST_USER,
            to=[data["to_email"]],
        )
        email.send(fail_silently=False)


# Parse the CloudAMQP URL
cloudamqp_url = settings.CLOUDAMPURL

params = pika.URLParameters(cloudamqp_url)


def get_rabbitmq_connection():
    return pika.BlockingConnection(params)
