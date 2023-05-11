from flask import Flask, request, jsonify, redirect
import os
import json
from functools import wraps
from datetime import datetime
from helper_modules.shortener_helpers import is_valid_url, generate_unique_id

# Get the base URL from an environment variable, or use default value
BASE_URL = os.environ.get("BASE_URL", "http://localhost:3000")

class URLShortenerService:

    """
    A URL shortening service implemented using the Flask framework.

    Attributes:
        url_data (dict): A dictionary storing unique IDs and their corresponding URLs.
        app (Flask): A Flask application instance.
        auth_service (AuthService): An instance of the AuthService class that provides authentication services.
    """

    def __init__(self, auth_service):

        """
        Initialize the URLShortenerApp instance and set up the routes.
        """

        self.auth_service = auth_service
        self.data_file = 'url_data/url_data.json'
        self.url_data = self._load_data()
        self.app = Flask(__name__)
        self.app.before_request(self.check_jwt) # add the check_jwt method to be called before each request
        self.setup_routes()

    def setup_routes(self):

        """
        Set up the route handlers for the Flask application.
        """

        self.app.add_url_rule('/<string:id>', 'redirect_url', self.redirect_url, methods=['GET'])
        self.app.add_url_rule('/', 'serve_index', self.serve_index, methods=['GET'])
        self.app.add_url_rule('/<string:id>', 'update_url', self.update_url, methods=['PUT'])
        self.app.add_url_rule('/<string:id>', 'delete_url', self.delete_url, methods=['DELETE'])
        self.app.add_url_rule('/keys', 'get_all_keys', self.get_all_keys, methods=['GET'])
        self.app.add_url_rule('/', 'create_short_url', self.create_short_url, methods=['POST'])
        self.app.add_url_rule('/', 'unsupported_delete', self.unsupported_delete, methods=['DELETE'])
        self.app.add_url_rule('/search/<string:uri>', 'search_uri', self.search_uri, methods=['GET'])

    def _load_data(self):
        if os.path.exists(self.data_file):
            with open(self.data_file, "r") as file:
                return json.load(file)
        else:
            return {}
        
    def _save_data(self):
        with open(self.data_file, "w") as file:
            json.dump(self.url_data, file)

    def admin_required(f):

        """"
        A decorator that checks if the JWT token in the request's Authorization header has an admin role.
        If the user is not an admin, return a JSON error response with a 403 status code.

        Args:
        f (function): The function to be decorated.

        Returns:
        decorated_function (function): The decorated function that checks for admin privileges.
        """

        @wraps(f)
        def decorated_function(self, *args, **kwargs):
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[-1]
            payload = self.auth_service.validate_jwt(token)
            if payload.get("role") != "admin":
                return jsonify({'error': 'Admin privileges required'}), 403
            return f(self, *args, **kwargs)
        return decorated_function

    def check_jwt(self):

        """
        Check if the JWT token in the request's Authorization header is valid.
        If the token is invalid or not provided, return a JSON error response.

        The check_jwt method is called before each request (see __init__ method), 
        this ensures that the JWT token is validated and returns the required 401 "unauthorized" 
        or 403 "forbidden" status when necessary.
        """

        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Missing Authorization header'}), 401

        token = auth_header.split(' ')[-1]
        payload = self.auth_service.validate_jwt(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401

    def redirect_url(self, id):

        """
        Redirect the user to the original URL associated with the given ID.
        Args:
            id (str): The unique identifier of the shortened URL.
        Returns:
            response (redirect): A redirect response to the original URL if found,
                                 a JSON response with an error message otherwise.
        """

        if id in self.url_data:
            return redirect(self.url_data[id]['url']), 301
        else:
            return jsonify({"error": "URL not found"}), 404

    @admin_required
    def serve_index(self):

        """
        Retrieve all stored URLs and their corresponding data from the url_data dictionary and generates a list of dictionaries. 
        Sort the list of dictionaries by the timestamp of creation in descending order.
        Returns:
            response (json): A JSON response containing the sorted list of URLs
        """

        short_urls = [{
            "generated_uri": key,
            "url": f"{BASE_URL}/{key}",
            "created_at": self.url_data[key]["created_at"],
            "original_url": self.url_data[key]["url"]
            }
            for key in self.url_data
        ]
        short_urls = sorted(short_urls, key=lambda x: x['created_at'], reverse=True)
        
        return jsonify(short_urls), 200
    
    def search_uri(self, uri):

        """
        Search for the given URI in the url_data dictionary.
        Args:
            uri (str): The URI to search for.
        Returns:
            response (json): A JSON response containing the original URL, shortened URI, and timestamp if found,
                             an error message otherwise.
        """

        if uri in self.url_data:
            original_url = self.url_data[uri]['url']
            shortened_url = f"{BASE_URL}/{uri}"
            timestamp = self.url_data[uri]['created_at']
            return jsonify({'original_url': original_url, 'shortened_url': shortened_url, 'timestamp': timestamp}), 200
        else:
            return jsonify({'error': 'URI not found'}), 404
        
    @admin_required
    def update_url(self, id):

        """
        Update the URL associated with the given ID.
        Args:
            id (str): The ID of the URL to update.
        Returns:
            response (json): A JSON response containing a message or error.
        """

        data = request.get_json()
        if data is None:
            return jsonify({'error': 'Invalid JSON'}), 400
        url = data.get('url')
        if url is not None and is_valid_url(url):
            if id in self.url_data:
                self.url_data[id] = {"url": url, "created_at": self.url_data[id]["created_at"]}
                self._save_data()
                return jsonify({'message': 'Updated'}), 200
            else:
                return jsonify({'error': 'Not Found'}), 404
        else:
            return jsonify({'error': 'Invalid URL'}), 400

    @admin_required
    def delete_url(self, id):

        """
        Delete the URL associated with the given ID.
        Args:
            id (str): The ID of the URL to delete.
        Returns:
            response: An HTTP response with a status code.
        """

        if id in self.url_data:
            del self.url_data[id]
            self._save_data()
            return '', 204
        else:
            return jsonify({'error': 'Not Found'}), 404

    def get_all_keys(self):

        """
        Retrieve all stored URL identifiers.
        Returns:
            response (json): A JSON response containing a list of URL identifiers.
        """

        if len(self.url_data.keys()) == 0:
            return "No URL identifiers found.", 404
        else:
            return jsonify(list(self.url_data.keys())), 200

    @admin_required
    def create_short_url(self):

        """
        Create a short URL for the given long URL. 
        If the URL already exists in the url_data dictionary, return an error message.
        
        Returns:
            response (json): A JSON response containing the short URL identifier, an error message if the URL already exists,
                            or an error message for an invalid URL.
        """

        data = request.get_json()
        if data is None:
            return jsonify({'error': 'Invalid JSON'}), 400
        url = data.get('url')
        if url is None or not is_valid_url(url):
            return jsonify({'error': 'Invalid URL'}), 400

        if existing_id := next(
            (id for id, value in self.url_data.items() if value['url'] == url),
            None,
        ):
            short_url = f"{BASE_URL}/{existing_id}"
            generated_uri = existing_id
            return jsonify({'error': 'URL already exists', 'short_url': short_url, 'generated_uri': generated_uri}), 409

        try:
            unique_id = generate_unique_id(self.url_data)
            self.url_data[unique_id] = {"url": url, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            self._save_data()
            short_url = f"{BASE_URL}/{unique_id}"
            generated_uri = unique_id

            return jsonify({'short_url': short_url, 'generated_uri': generated_uri}), 201
        except ValueError as e:
            error_msg = f"An internal server error occurred while generating a unique identifier: {str(e)}. Function: create_short_url(). Module: url_shortener.py"
            return jsonify({'error': error_msg}), 500

    @admin_required
    def unsupported_delete(self):

        """
        Handle unsupported DELETE requests without an identifier.
        Returns:
            response (json): A JSON response containing an error message.
        """

        return jsonify({'error': 'Method not supported'}), 404

    def run(self, *args, **kwargs):

        """
        Run the Flask application with the given arguments and keyword arguments.
        The host parameter is set to '0.0.0.0' to make the application accessible to any address.
        Args:
            *args: Variable-length argument list.
            **kwargs: Arbitrary keyword arguments.
        """

        self.app.run(host='0.0.0.0', *args, **kwargs)
