import hashlib
from uuid_extensions import uuid7
from datetime import datetime, timedelta, timezone
from enum import Enum

from peewee import (
    BooleanField,
    CharField,
    DateTimeField,
    Model,
    MySQLDatabase,
    UUIDField
)

db = MySQLDatabase(
    "authenticator_db",
    user="root",
    password="secret_password",
    host="127.0.0.1",
    port=3306,
)

DEFAULT_TOKEN_TTL = timedelta(hours=1)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Role(Enum):
    ADMINISTRATOR = "administrator"
    MAINTAINER = "maintainer"


class BaseModel(Model):
    class Meta:
        database = db


class User(BaseModel):
    uid = UUIDField(primary_key=True, default=uuid7)
    username = CharField(max_length=255, unique=True)
    password = CharField(max_length=255, null=True)
    role = CharField(max_length=255, default=Role.MAINTAINER.value)
    is_active = BooleanField(null=False, default=False)

    class Meta:
        table_name = "user"


class TokenBlacklist(BaseModel):
    token_hash = CharField(max_length=64, primary_key=True)
    date_added = DateTimeField(default=utcnow)
    expires_at = DateTimeField(index=True)

    class Meta:
        table_name = "token_blacklist"


class DBConnection:

    def __init__(self):
        db.connect(reuse_if_open=True)
        db.create_tables([User, TokenBlacklist], safe=True)

    def GetUser(self, username):
        return User.get_or_none(User.username == username)

    def GetUsers(self):
        return list(User.select().order_by(User.username))

    def CreateUser(self, username, role=Role.MAINTAINER):
        if self.GetUser(username) is not None:
            return None
        return User.create(
            uid=uuid7(),
            username=username,
            password=None,
            role=Role(role),
            is_active=False,
        )

    def ActivateUser(self, username, password):
        updated = (
            User.update(password=password, is_active=True)
            .where(User.username == username)
            .execute()
        )
        return updated > 0

    def DeactivateUser(self, username):
        updated = (
            User.update(password=None, is_active=False)
            .where(User.username == username)
            .execute()
        )
        return updated > 0

    @staticmethod
    def _hash_token(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _delete_expired(self):
        TokenBlacklist.delete().where(TokenBlacklist.expires_at <= utcnow()).execute()

    def AddTokenBlacklist(self, token):
        self._delete_expired()
        expires_at = utcnow() + DEFAULT_TOKEN_TTL
        TokenBlacklist.insert(
            token_hash=self._hash_token(token),
            date_added=utcnow(),
            expires_at=expires_at,
        ).on_conflict_ignore().execute()

    def IsTokenBlacklisted(self, token):
        return (
            TokenBlacklist.select()
            .where(
                TokenBlacklist.token_hash == self._hash_token(token),
                TokenBlacklist.expires_at > utcnow(),
            )
            .exists()
        )

