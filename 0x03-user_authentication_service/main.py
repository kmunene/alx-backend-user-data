#!/usr/bin/env python3
"""
Testing
"""

import requests

EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"
BASE_URL = "http://0.0.0.0:5000"


def register_user(email: str, password: str) -> None:
    """Testing user registration"""
    url = f"{BASE_URL}/users"
    payload = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=payload)

    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "user created"}

    response = requests.post(url, data=payload)
    assert response.status_code == 400
    assert response.json() == {"message": "email already registered"}


def log_in_wrong_password(email: str, password: str) -> None:
    """Testing user's wrong credentials"""
    url = f"{BASE_URL}/sessions"
    payload = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=payload)
    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """Testing user login"""
    url = f"{BASE_URL}/sessions"
    payload = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=payload)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "logged in"}
    session_id = response.cookies.get('session_id')
    return session_id


def profile_unlogged() -> None:
    """Testing for an unlooged user"""
    url = f"{BASE_URL}/profile"

    response = requests.get(url)
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """Testing when the user is logged in"""
    url = f"{BASE_URL}/profile"
    payload_cookies = {
        "session_id": session_id
    }

    response = requests.get(url, cookies=payload_cookies)
    assert response.status_code == 200


def log_out(session_id: str) -> None:
    """Testing log out endpoint"""
    url = f"{BASE_URL}/sessions"

    payload_cookies = {
        "session_id": session_id
    }
    response = requests.delete(url, cookies=payload_cookies)
    assert response.status_code == 200
    assert response.json() == {"message": "Bienvenue"}


def reset_password_token(email: str) -> str:
    """Testing the reset password endpoint"""
    url = f"{BASE_URL}/reset_password"

    payload = {
        "email": email
    }
    response = requests.post(url, data=payload)
    assert response.status_code == 200
    assert "reset_token" in response.json()
    assert response.json() == {
        "email": email,
        "reset_token": response.json()["reset_token"]
        }
    return response.json().get('reset_token')


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Testing for password update"""
    url = f"{BASE_URL}/reset_password"

    payload = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password
    }
    response = requests.put(url, data=payload)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "Password updated"}


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
