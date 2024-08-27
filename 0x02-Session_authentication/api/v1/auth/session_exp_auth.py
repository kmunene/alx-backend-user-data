#!/usr/bin/env python3
"""Module"""

from api.v1.auth.session_auth import SessionAuth
import os
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """session expiry class"""
    def __init__(self):
        """__init__"""
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION', '0'))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """creating a session"""
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        session_dictonary = {
            "user_id": user_id,
            "created_at": datetime.now()
        }

        self.user_id_by_session_id[session_id] = session_dictonary
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """getting user_id"""
        if session_id is None:
            return None
        session_dict = self.user_id_by_session_id.get(session_id)
        if not session_dict:
            return None

        if self.session_duration <= 0:
            return session_dict['user_id']
        created_at = session_dict['created_at']
        if not created_at:
            return None

        expiry_time = created_at + timedelta(seconds=self.session_duration)
        if datetime.now() > expiry_time:
            return None

        return session_dict['user_id']
