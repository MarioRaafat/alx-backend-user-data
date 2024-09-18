#!/usr/bin/env python3
"""Authentication module for the API.
"""
import re
from typing import List, TypeVar
from flask import request


class Auth:
    """Authentication class.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if a path requires authentication.
        """
        if not path or not excluded_paths:
            return True

        for exclusion_path in excluded_paths:
            exclusion_path = exclusion_path.strip()
            if not exclusion_path:
                continue
            
            # Build pattern based on exclusion path
            if exclusion_path.endswith('*'):
                pattern = re.escape(exclusion_path[:-1]) + '.*'
            elif exclusion_path.endswith('/'):
                pattern = re.escape(exclusion_path[:-1]) + '/.*'
            else:
                pattern = re.escape(exclusion_path) + '/.*'
            
            # Match the path against the pattern
            if re.fullmatch(pattern, path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Gets the authorization header field from the request.
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Gets the current user from the request.
        """
        return None