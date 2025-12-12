# config.py

import os

# Base URL for the API service
# ASSUMPTION: API is running locally (e.g., via Docker) on port 5000
BASE_URL = os.getenv("BASE_API_URL", "http://localhost:5000")

# HTTP Status Codes
HTTP_200_OK = 200
HTTP_201_CREATED = 201
HTTP_400_BAD_REQUEST = 400
HTTP_401_UNAUTHORIZED = 401
HTTP_403_FORBIDDEN = 403
HTTP_500_SERVER_ERROR = 500

# API Endpoints
ENDPOINT_REGISTER = "/register"
ENDPOINT_CONFIRM = "/confirm_registration" # Takes path variable
ENDPOINT_LOGIN = "/login"
ENDPOINT_LOGOUT = "/logout"
ENDPOINT_USER_MNGT = "/user_mngt_user" # Used for GET, PUT, DELETE
ENDPOINT_FORGET_PASS = "/forget_password"
ENDPOINT_RESEND_LINK = "/resend_registration_link"
ENDPOINT_VERSION = "/version"

# Default valid profile data for positive tests (BVA mid-range valid data)
VALID_PROFILE_DATA = {
    "first_name": "TestAlpha",
    "last_name": "TestBeta",
    "address1": "123 Test Avenue",
    "address2": "Apt 2B",
    "city": "TestCity",
    "state": "TestState",
    "country": "India",
    "pin_code": "411001",
    "contact_country_code": "091", # 3 digits (Valid range: 3)
    "contact_number": "9876543210" # 10 digits (Valid range: 10)
}