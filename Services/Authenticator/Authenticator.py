import hashlib


class Authenticator:
    def __init__(self, DBConnection):
        self.DBConnection = DBConnection

    def _Hash(self, password):
        return hashlib.md5(password.encode()).hexdigest()

    def _HashMatch(self, password, hash):
        return hashlib.md5(password.encode()).hexdigest() == hash

    def _DecodeToken(self, token):
        pass
    def _EncodeToken(self, username, role):
        pass
    def _IsUserExists(self, username):
        pass
    def _GetUsers(self):
        pass
    def _ActivateUser(self, username, password):
        pass
    def _DeactivateUser(self, username):
        pass
    def _AddUser(self, username, role):
        pass
    def _DeleteToken(self, token):
        pass
    def _ValidateToken(self, token):
        pass
    def _IsTokenBlacklisted(self, token):
        pass
    def _BlacklistToken(self, token):
        pass
    def _RemoveUser(self, username):
        pass
    def Login(self, loginRequest):
        pass
    def ListingUsers(self, ListingRequest):
        pass
    def CreateUser(self, createUserRequest):
        pass
    def ActivateUser(self, activateUserRequest):
        pass
    def DeactivateUser(self, deactivateUserRequest):
        pass
    def ValidateToken(self, validateTokenRequest):
        pass
    def DeleteToken(self, deleteTokenRequest):
        pass