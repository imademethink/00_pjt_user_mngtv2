# http_client_helper.py

import requests
import json
from config import BASE_URL, HTTP_500_SERVER_ERROR


class APIResponse:
    """A minimal wrapper for the requests.Response object, standardizing access."""

    def __init__(self, status_code, content):
        self.status_code = status_code
        self._content = content
        # CRITICAL FIX: Pre-decode the JSON robustly on initialization
        try:
            self._json_data = json.loads(self._content)
        except (json.JSONDecodeError, TypeError):
            self._json_data = {"message": f"Response body is not valid JSON. Raw content: {self._content}"}

    def json(self):
        """Returns the decoded JSON body (the correct method signature)."""
        return self._json_data

    def get_data(self, as_text=True):
        """Returns the raw response text for logging failures."""
        return self._content


def user_mngt_request(method, endpoint, params=None, data=None):
    """
    Performs an HTTP request to the live API service running externally.
    This is the core of the black-box testing framework.
    """
    url = f"{BASE_URL}{endpoint}"

    try:
        response = requests.request(
            method,
            url,
            params=params,
            json=data,
            timeout=10  # Set a reasonable timeout
        )
        # Return our standardized wrapper object
        return APIResponse(response.status_code, response.text)

    except requests.exceptions.RequestException as e:
        # Handle connection errors (API not running or unreachable)
        print(f"FATAL: API Connection Error: {e}")
        return APIResponse(
            HTTP_500_SERVER_ERROR,
            f'{{"message": "API service is unavailable at {BASE_URL}. Connection failed: {str(e)}"}}'
        )