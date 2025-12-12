# conftest.py

import pytest
import time
import uuid
import re
import os
import sys

# --------------------------------------------------------------------------
# CRITICAL FIX: Ensure the project root is in sys.path to resolve local imports
# (config.py and http_client_helper.py)
# --------------------------------------------------------------------------
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from http_client_helper import user_mngt_request
from config import *


# --------------------------------------------------------------------------

# Helper to extract token from confirmation link
def extract_token(link):
    match = re.search(r'/confirm_registration/([^/]+)$', link)
    return match.group(1) if match else None


# --- Setup/Teardown Fixtures for Black-Box Testing ---

@pytest.fixture(scope="session", autouse=True)
def api_service_health_check():
    """
    Checks if the external API service is reachable before running any tests.
    This is the session-level setup (no database manipulation required).
    """
    print(f"\n--- Checking API health at {BASE_URL} ---")
    response = user_mngt_request('GET', ENDPOINT_VERSION)
    if response.status_code != HTTP_200_OK:
        pytest.fail(f"FATAL: API service not reachable or returned non-200. "
                    f"Check your deployment is running. Status: {response.status_code}. Body: {response.get_data()}")
    print("--- API Health Check Successful ---")

    yield


@pytest.fixture(scope="function")
def api_client():
    """
    Function-scoped fixture that provides the function to make external HTTP requests.
    """
    yield user_mngt_request


# --- User Lifecycle Fixtures ---

@pytest.fixture(scope="function")
def register_test_user(api_client):
    """Registers a user but DOES NOT confirm them."""
    unique_id = uuid.uuid4().hex[:8]
    email = f"u_{unique_id}@reg.com"
    password = "pYtEsT"

    response = api_client('POST', ENDPOINT_REGISTER, data={"email": email, "password": password})
    assert response.status_code == HTTP_201_CREATED, f"Registration failed: {response.status_code}. Body: {response.get_data(as_text=True)}"

    user_data = {
        "email": email,
        "password": password,
        "confirmation_link": response.json().get('confirmation_link'),
        "session_key": None,
        "user_id": None
    }
    yield user_data


@pytest.fixture(scope="function")
def confirmed_test_user(api_client, register_test_user):
    """Registers and CONFIRMS a user, but DOES NOT log them in."""
    user_data = register_test_user
    token = extract_token(user_data['confirmation_link'])

    response = api_client('GET', f"{ENDPOINT_CONFIRM}/{token}")
    assert response.status_code == HTTP_200_OK, f"Confirmation failed: {response.status_code}. Body: {response.get_data(as_text=True)}"

    yield user_data


@pytest.fixture(scope="function")
def logged_in_test_user(api_client, confirmed_test_user):
    """Registers, Confirms, LOGS IN, and populates mandatory profile fields for clean use."""
    user_data = confirmed_test_user

    # 1. Login
    response = api_client('POST', ENDPOINT_LOGIN, data={"email": user_data['email'], "password": user_data['password']})
    assert response.status_code == HTTP_200_OK, f"Login failed: {response.status_code}. Body: {response.get_data(as_text=True)}"

    # 2. Update user_data with session details
    response_json = response.json()
    user_data['session_key'] = response_json.get('session_key')
    user_data['user_id'] = response_json.get('user_id')
    user_data['profile_data'] = VALID_PROFILE_DATA.copy()  # Store a mutable copy of valid data

    # 3. Update profile with mandatory data
    query_params = {
        "email": user_data['email'],
        "session_key": user_data['session_key']
    }
    response = api_client('PUT', ENDPOINT_USER_MNGT, params=query_params, data=user_data['profile_data'])
    assert response.status_code == HTTP_200_OK, f"Initial profile update failed: {response.status_code}. Body: {response.get_data(as_text=True)}"

    yield user_data