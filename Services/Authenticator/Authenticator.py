import json
import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from uuid import UUID, uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError,
)
from peewee import IntegrityError

from pb.authenticator_pb2 import (
    LoginResponse,
    ListingResponse,
    CreateUserResponse,
    ActivateUserResponse,
    DeactivateUserResponse,
    ValidateTokenResponse,
    DeleteTokenResponse,
)

from DBConnection import Role


class Authenticator:
    ALGORITHM = "HS256"

    def __init__(self, db_connection, issuer=None):
        self.DBConnection = db_connection
        self._ph = PasswordHasher()

        self._secret = os.environ["JWT_SECRET_KEY"]
        self._issuer = issuer or os.environ["JWT_ISSUER"]

    def _DecodeToken(self, token):
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=[self.ALGORITHM],
                issuer=self._issuer,
                options={
                    "require": ["iss", "sub", "exp", "jti", "role"],
                },
            )

            UUID(claims["sub"])
            UUID(claims["jti"])

            if not isinstance(claims["role"], str):
                return None

            return claims

        except (
                jwt.InvalidTokenError,
                KeyError,
                TypeError,
                ValueError,
        ):
            return None

    def _CreateToken(
            self, iss, user_uuid, role, ttl=timedelta(hours=1)
    ):
        now = datetime.now(timezone.utc)

        payload = {
            "iss": iss,
            "sub": str(user_uuid),
            "exp": now + ttl,
            "jti": str(uuid4()),
            "role": role.value if isinstance(role, Enum) else str(role),
        }

        return jwt.encode(
            payload,
            self._secret,
            algorithm=self.ALGORITHM,
        )

    def _IsUserExists(self, username):
        return self.DBConnection.GetUser(username) is not None

    def _ActivateUser(self, username, password):
        if not password:
            return False

        password_hash = self._ph.hash(password)
        return self.DBConnection.ActivateUser(
            username, password_hash
        )

    def _AddUser(self, username, role):
        try:
            if isinstance(role, Role):
                role_value = role.value
            else:
                role_value = Role(role).value

            return self.DBConnection.CreateUser(
                username, role_value
            )
        except (ValueError, IntegrityError):
            return None

    def _IsTokenBlacklisted(self, token):
        claims = self._DecodeToken(token)
        if claims is None:
            return True

        return self.DBConnection.IsTokenBlacklisted(claims["jti"])

    def _ValidateToken(self, token):
        claims = self._DecodeToken(token)

        if claims is None:
            return None

        if self.DBConnection.IsTokenBlacklisted(claims["jti"]):
            return None

        user = self.DBConnection.GetUserByUid(claims["sub"])

        if user is None or not user.is_active:
            return None

        if user.role != claims["role"]:
            return None

        return claims

    def _BlacklistToken(self, claims):
        if claims is None:
            return False

        expires_at = datetime.fromtimestamp(
            claims["exp"], tz=timezone.utc
        ).replace(tzinfo=None)

        self.DBConnection.AddTokenBlacklist(claims["jti"], expires_at=expires_at)

        return True

    def _CheckPassword(self, username, password):
        user = self.DBConnection.GetUser(username)

        if user is None or not user.is_active or not user.password:
            return False

        try:
            return self._ph.verify(user.password, password)
        except (
                VerifyMismatchError,
                VerificationError,
                InvalidHashError,
                TypeError,
        ):
            return False

    def _IsAdministrator(self, claims):
        return claims is not None and (
                claims["role"] == Role.ADMINISTRATOR.value
        )

    def _IsUserActivated(self, user):
        return user.is_active


    def Login(self, loginRequest):
        user = self.DBConnection.GetUser(loginRequest.username)

        if user is None:
            return LoginResponse(StatusCode="UNAUTHENTICATED")

        if not self._CheckPassword(loginRequest.username, loginRequest.password):
            return LoginResponse(StatusCode="UNAUTHENTICATED")

        if not self._IsUserActivated(user):
            return LoginResponse(StatusCode="PERMISSION_DENIED")

        token = self._CreateToken(
            self._issuer,
            user.uid,
            user.role,
        )

        return LoginResponse(
            StatusCode="OK",
            token=token,
        )

    def ListingUsers(self, listingRequest):
        claims = self._ValidateToken(listingRequest.token)

        if claims is None:
            return ListingResponse(StatusCode="UNAUTHENTICATED")

        if not self._IsAdministrator(claims):
            self._BlacklistToken(claims)
            return ListingResponse(StatusCode="PERMISSION_DENIED")

        users = [
            {
                "uid": str(user.uid),
                "username": user.username,
                "role": user.role,
                "is_active": user.is_active,
            }
            for user in self.DBConnection.GetUsers()
        ]

        return ListingResponse(
            StatusCode="OK",
            list=json.dumps(users),
        )

    def CreateUser(self, createUserRequest):
        claims = self._ValidateToken(createUserRequest.token)

        if claims is None:
            return CreateUserResponse(StatusCode="UNAUTHENTICATED")

        if not self._IsAdministrator(claims):
            return CreateUserResponse(StatusCode="PERMISSION_DENIED")

        if not createUserRequest.username:
            return CreateUserResponse(StatusCode="INVALID_ARGUMENT")

        try:
            role = Role(createUserRequest.role)
        except ValueError:
            return CreateUserResponse(StatusCode="INVALID_ARGUMENT")

        user = self._AddUser(createUserRequest.username, role)

        if user is None:
            return CreateUserResponse(StatusCode="ALREADY_EXISTS")

        return CreateUserResponse(StatusCode="OK")

    def ActivateUser(self, activateUserRequest):
        if not activateUserRequest.username or not activateUserRequest.password:
            return ActivateUserResponse(StatusCode="INVALID_ARGUMENT")

        if not self._IsUserExists(activateUserRequest.username):
            return ActivateUserResponse(StatusCode="NOT_FOUND")

        user = self.DBConnection.GetUser(self, activateUserRequest.username)

        if self._IsUserActivated(user):
            return LoginResponse(StatusCode="PERMISSION_DENIED")

        if user.password is not None:
            return LoginResponse(StatusCode="PERMISSION_DENIED")

        success = self._ActivateUser(
            activateUserRequest.username,
            activateUserRequest.password,
        )

        if success:
            return ActivateUserResponse(StatusCode="OK")

        return ActivateUserResponse(StatusCode="FAILED")

    def DeactivateUser(self, deactivateUserRequest):
        claims = self._ValidateToken(deactivateUserRequest.token)

        if claims is None:
            return DeactivateUserResponse(StatusCode="UNAUTHENTICATED")

        if not self._IsAdministrator(claims):
            return DeactivateUserResponse(StatusCode="PERMISSION_DENIED")

        if not self._IsUserExists(deactivateUserRequest.username):
            return DeactivateUserResponse(StatusCode="NOT_FOUND")

        success = self.DBConnection.DeactivateUser(deactivateUserRequest.username)

        if success:
            return DeactivateUserResponse(StatusCode="OK")

        return DeactivateUserResponse(StatusCode="FAILED")

    def ValidateToken(self, validateTokenRequest):
        claims = self._ValidateToken(validateTokenRequest.token)

        if claims is None:
            return ValidateTokenResponse(StatusCode="UNAUTHENTICATED")

        return ValidateTokenResponse(
            StatusCode="OK",
            sub=claims["sub"],
            role=claims["role"],
        )

    def BlacklistToken(self, deleteTokenRequest):
        claims = self._ValidateToken(deleteTokenRequest.token)

        if claims is None:
            return DeleteTokenResponse(StatusCode="UNAUTHENTICATED")

        success = self._BlacklistToken(deleteTokenRequest.token)

        if success:
            return DeleteTokenResponse(StatusCode="OK")
        return DeleteTokenResponse(StatusCode="FAILED")
