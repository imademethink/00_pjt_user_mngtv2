# test_user_mngt_v2.py

import pytest
from config import *  # --- Assertion Helper ---


def assert_response_success(response, expected_code):
    """Helper to assert success codes and provide detailed failure output."""
    assert response.status_code == expected_code, (
        f"TEST FAILED: Expected Status Code {expected_code}, "
        f"Got {response.status_code}.\n"
        f"Response Body: {response.get_data(as_text=True)}"
    )


def assert_response_failure(response, expected_code, expected_message_part=None):
    """Helper to assert failure codes and check for a specific message fragment."""
    assert response.status_code == expected_code, (
        f"TEST FAILED: Expected Status Code {expected_code}, "
        f"Got {response.status_code}.\n"
        f"Response Body: {response.get_data(as_text=True)}"
    )
    if expected_message_part:
        # Use .json() method for the robust APIResponse object
        response_message = response.json().get('message', '')
        assert expected_message_part in response_message, (
            f"TEST FAILED: Expected message part '{expected_message_part}' "
            f"not found in response message: '{response_message}'.\n"
            f"Response Body: {response.get_data(as_text=True)}"
        )


# --- V1/V2 Common APIs (Sanity Checks) ---

def test_get_version_positive(api_client):
    """API-001: Tests successful retrieval of system version."""
    response = api_client('GET', ENDPOINT_VERSION)
    assert_response_success(response, HTTP_200_OK)
    assert response.json().get('version') == "2.0.0"


def test_register_and_confirm_positive(api_client, register_test_user):
    """Tests R-P-01 and C-P-01: Full V1 flow."""
    user_data = register_test_user
    token = user_data['confirmation_link'].split('/')[-1]

    # Confirmation
    response = api_client('GET', f"{ENDPOINT_CONFIRM}/{token}")
    assert_response_success(response, HTTP_200_OK)


# --- V2 API-004: Login (Updated) ---

def test_login_positive(api_client, confirmed_test_user):
    """Tests L-P-01: Successful login with session key."""
    response = api_client('POST', ENDPOINT_LOGIN, data=confirmed_test_user)
    assert_response_success(response, HTTP_200_OK)
    assert 'session_key' in response.json()
    assert 'user_id' in response.json()


def test_login_unconfirmed_negative(api_client, register_test_user):
    """Tests L-N-06: Login attempt with unconfirmed user."""
    response = api_client('POST', ENDPOINT_LOGIN, data=register_test_user)
    assert_response_failure(response, HTTP_403_FORBIDDEN, "not confirmed")


def test_login_invalid_credentials_negative(api_client):
    """Tests L-N-07: Login attempt with invalid password for a non-existent user."""
    invalid_data = {"email": "nonexistent@test.com", "password": "wrongpassword"}
    response = api_client('POST', ENDPOINT_LOGIN, data=invalid_data)
    assert_response_failure(response, HTTP_401_UNAUTHORIZED, "Invalid email or password")


# --- V2 API-005: Logout (New) ---

def test_logout_positive(api_client, logged_in_test_user):
    """Tests O-P-01: Successful logout."""
    logout_data = {
        "email": logged_in_test_user['email'],
        "session_key": logged_in_test_user['session_key']
    }
    response = api_client('POST', ENDPOINT_LOGOUT, data=logout_data)
    assert_response_success(response, HTTP_200_OK)

    # Secondary check: The old session key should now be invalid for a secure endpoint (e.g., GET user details)
    response_check = api_client('GET', ENDPOINT_USER_MNGT, params=logout_data)
    assert_response_failure(response_check, HTTP_401_UNAUTHORIZED, "Session is inactive")


def test_logout_invalid_session_negative(api_client, logged_in_test_user):
    """Tests O-N-01/O-N-02: Invalid session or mismatched email."""
    invalid_data = {
        "email": "wrong@email.com",
        "session_key": logged_in_test_user['session_key']
    }
    response = api_client('POST', ENDPOINT_LOGOUT, data=invalid_data)
    assert_response_failure(response, HTTP_401_UNAUTHORIZED, "Invalid email or session key")


def test_logout_missing_fields_negative(api_client):
    """Tests O-N-03: Missing required fields."""
    response = api_client('POST', ENDPOINT_LOGOUT, data={"email": "test@test.com"})
    assert_response_failure(response, HTTP_400_BAD_REQUEST, "required")


# --- V2 API-006: Get User Details (New) ---

def test_get_user_positive(api_client, logged_in_test_user):
    """Tests successful retrieval of user profile."""
    query_params = {
        "email": logged_in_test_user['email'],
        "session_key": logged_in_test_user['session_key']
    }
    response = api_client('GET', ENDPOINT_USER_MNGT, params=query_params)
    assert_response_success(response, HTTP_200_OK)

    # Assert mandatory fields are present and password is excluded
    user_data = response.json()
    assert user_data.get('first_name') == VALID_PROFILE_DATA['first_name']
    assert 'password' not in user_data


# --- V2 API-007: Update User Details (New & BVA) ---

def test_update_user_positive_full(api_client, logged_in_test_user):
    """Tests U-P-01: Successful update of all fields with valid, mid-range data."""
    query_params = {
        "email": logged_in_test_user['email'],
        "session_key": logged_in_test_user['session_key']
    }
    new_data = VALID_PROFILE_DATA.copy()
    new_data['address1'] = "456 New Road"

    response = api_client('PUT', ENDPOINT_USER_MNGT, params=query_params, data=new_data)
    assert_response_success(response, HTTP_200_OK)

    # Verify the change
    response_get = api_client('GET', ENDPOINT_USER_MNGT, params=query_params)
    assert response_get.json().get('address1') == "456 New Road"


def test_update_user_block_email_negative(api_client, logged_in_test_user):
    """Tests U-N-03: Attempt to update email."""
    query_params = {
        "email": logged_in_test_user['email'],
        "session_key": logged_in_test_user['session_key']
    }
    update_data = logged_in_test_user['profile_data'].copy()
    update_data["email"] = "new@email.com"  # Attempt to change email

    response = api_client('PUT', ENDPOINT_USER_MNGT, params=query_params, data=update_data)
    assert_response_failure(response, HTTP_400_BAD_REQUEST, "Email field cannot be changed")


@pytest.mark.parametrize("invalid_data, expected_code", [
    # U-N-04: Invalid first/last name (alphanumeric and short) - FIX applied here
    ({"first_name": "Test1", "last_name": "TooShort"}, HTTP_400_BAD_REQUEST),
    # U-N-05: Contact Min-1
    ({"contact_country_code": "01", "contact_number": "123456789"}, HTTP_400_BAD_REQUEST),
    # U-N-06: Contact Max+1
    ({"contact_country_code": "0001", "contact_number": "12345678901"}, HTTP_400_BAD_REQUEST),
    # U-N-07: Address/City boundary (Min-1 and Max+1)
    ({"address1": "123", "city": "TooLongCityName1234567890"}, HTTP_400_BAD_REQUEST),
    # U-N-04: Further BVA on length (Min-1)
    ({"first_name": "ABCD", "last_name": "Short"}, HTTP_400_BAD_REQUEST),
    # U-N-04: Further BVA on length (Max+1)
    ({"first_name": "A" * 26, "last_name": "B" * 26}, HTTP_400_BAD_REQUEST),
])
def test_update_user_boundary_negative(api_client, logged_in_test_user, invalid_data, expected_code):
    """Tests U-N-04 through U-N-07 BVA checks."""
    query_params = {
        "email": logged_in_test_user['email'],
        "session_key": logged_in_test_user['session_key']
    }

    # CRITICAL FIX: Ensure payload is complete by starting with valid data
    # and only overriding the specific invalid fields being tested.
    payload = logged_in_test_user['profile_data'].copy()
    payload.update(invalid_data)

    response = api_client('PUT', ENDPOINT_USER_MNGT, params=query_params, data=payload)

    assert_response_failure(response, expected_code, "Invalid input format")


# --- V2 API-008: Delete User (New) ---

def test_delete_user_positive(api_client, logged_in_test_user):
    """Tests successful user deletion."""
    delete_data = {
        "email": logged_in_test_user['email'],
        "password": logged_in_test_user['password'],
        "session_key": logged_in_test_user['session_key']
    }
    response = api_client('DELETE', ENDPOINT_USER_MNGT, data=delete_data)
    assert_response_success(response, HTTP_200_OK)

    # Secondary check: Login should now fail
    response_check = api_client('POST', ENDPOINT_LOGIN, data=logged_in_test_user)
    assert_response_failure(response_check, HTTP_401_UNAUTHORIZED, "Invalid email or password")


# --- V2 API-009: Forget Password (New) ---

def test_forget_password_positive(api_client, logged_in_test_user):
    """Tests FP-P-01: Successful password change."""
    new_pass = "654321"

    update_data = {
        "email": logged_in_test_user['email'],
        "session_key": logged_in_test_user['session_key'],
        "new_password": new_pass,
        "confirm_new_password": new_pass
    }
    response = api_client('PUT', ENDPOINT_FORGET_PASS, data=update_data)
    assert_response_success(response, HTTP_200_OK)

    # Secondary check: Verify login with new password
    response_success = api_client('POST', ENDPOINT_LOGIN,
                                  data={"email": logged_in_test_user['email'], "password": new_pass})
    assert_response_success(response_success, HTTP_200_OK)


def test_forget_password_mismatch_negative(api_client, logged_in_test_user):
    """Tests FP-N-02: Password mismatch."""
    update_data = {
        "email": logged_in_test_user['email'],
        "session_key": logged_in_test_user['session_key'],
        "new_password": "111111",
        "confirm_new_password": "222222"
    }
    response = api_client('PUT', ENDPOINT_FORGET_PASS, data=update_data)
    assert_response_failure(response, HTTP_400_BAD_REQUEST, "do not match")


def test_forget_password_invalid_length_negative(api_client, logged_in_test_user):
    """Tests FP-N-03: Password length invalid (BVA: 5 chars)."""
    update_data = {
        "email": logged_in_test_user['email'],
        "session_key": logged_in_test_user['session_key'],
        "new_password": "12345",
        "confirm_new_password": "12345"
    }
    response = api_client('PUT', ENDPOINT_FORGET_PASS, data=update_data)
    assert_response_failure(response, HTTP_400_BAD_REQUEST, "exactly 6 characters")


# --- V2 API-010: Resend Registration Link (New) ---

def test_resend_link_unconfirmed_positive(api_client, register_test_user):
    """Tests successful resend for an unconfirmed user."""
    # FIX: Include password in payload, assuming API requires authentication for this action
    resend_data = {
        "email": register_test_user['email'],
        "password": register_test_user['password']
    }

    # Keeping expected code as 200, as it's the most common "action success" code.
    response = api_client('POST', ENDPOINT_RESEND_LINK, data=resend_data)
    assert_response_success(response, HTTP_200_OK)
    assert "New registration link generated" in response.json().get('message')


def test_resend_link_confirmed_negative(api_client, confirmed_test_user):
    """Tests resend failure for an already confirmed user."""
    # FIX: Include password in payload, assuming API requires authentication for this action
    resend_data = {
        "email": confirmed_test_user['email'],
        "password": confirmed_test_user['password']
    }

    # Keeping expected code as 400 Bad Request, as the input state (confirmed user) makes the request invalid.
    response = api_client('POST', ENDPOINT_RESEND_LINK, data=resend_data)
    assert_response_failure(response, HTTP_400_BAD_REQUEST, "already confirmed")

