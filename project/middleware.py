from django.utils.deprecation import MiddlewareMixin


class JWTAuthCookieMiddleware:
    """
    Middleware for handling JWT authentication via cookies.

    This middleware extracts the JWT access token from cookies and sets
    it in the HTTP Authorization header for subsequent views. It skips
    this process for the user registration path.

    Attributes:
        get_response (callable): The next middleware or view to be called.
    """
    def __init__(self, get_response):
        """
        Initializes the JWTAuthCookieMiddleware.

        Args:
            get_response (callable): The next middleware or view to call.
        """
        self.get_response = get_response

    def __call__(self, request):
        """
        Processes the request to set the Authorization header from the cookie.

        This method checks for the presence of an access token in the cookies.
        If found, it sets the Authorization header accordingly. The middleware
        skips this process for the user registration path.

        Args:
            request (HttpRequest): The incoming HTTP request object.

        Returns:
            HttpResponse: The response from the next middleware or view.
        """
        # Skip setting Authorization header for user registration path
        if request.path.startswith('/api/v1/auth/userAdmin-register/'):
            response = self.get_response(request)
        else:    
            print(request.COOKIES)
            access_token = request.COOKIES.get('access_token')
            print(f"Access Token from Cookie: {access_token}")  # Debug: Print the access token
            if access_token:
                request.META['HTTP_AUTHORIZATION'] = f'Bearer {access_token}'
                print(f"Authorization Header: {request.META.get('HTTP_AUTHORIZATION')}")
            return self.get_response(request) 
        return response           