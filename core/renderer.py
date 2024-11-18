from rest_framework import renderers

import json

class UserRenderer(renderers.JSONRenderer):
    """
    Custom JSON renderer for formatting API responses.

    This renderer customizes the JSON response format. If the response data contains
    error details, it formats the response to include an 'errors' key with the error data.
    Otherwise, it returns the data as-is.

    Attributes:
        charset (str): The character set used for encoding the response. Defaults to 'utf-8'.

    Methods:
        render(data, accepted_media_type=None, renderer_context=None): 
            Converts the response data to JSON format. Formats error responses with an 'errors' key.
    """
    charset = 'utf-8'
    def render(self, data,accepted_media_type=None, renderer_context=None):
        """
    Custom renderer method to format the response data as JSON.

    Args:
        data (dict): The response data to be rendered.
        accepted_media_type (str, optional): The accepted media type (not used in this method). Defaults to None.
        renderer_context (dict, optional): Additional context for rendering (not used in this method). Defaults to None.

    Returns:
        str: A JSON-formatted string.
            - If the response contains an error ('ErrorDetail'), it wraps the errors in an 'errors' key.
            - Otherwise, it simply returns the data as is, in JSON format.
    """
        response =''
        if 'ErrorDetail' in str(data):
            response = json.dumps({'errors':data})
        else:
            response = json.dumps(data)

        return response 

