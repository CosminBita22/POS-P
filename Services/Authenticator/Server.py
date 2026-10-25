import grpc
from concurrent import futures
import time

from DBConnection import DBConnection
from Authenticator import Authenticator
from pb import authenticator_pb2_grpc
from pb import authenticator_pb2

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AuthenticatorServicer(authenticator_pb2_grpc.AuthenticatorServicer):
    def __init__(self):
        self.db = DBConnection()
        self.auth = Authenticator(self.db)

    def Login(self, request, context):
        logger.info("Login request received")
        return self.auth.Login(request)

    def ListingUsers(self, request, context):
        logger.info("ListingUsers request received")
        return self.auth.ListingUsers(request)

    def CreateUser(self, request, context):
        logger.info("CreateUser request received")
        return self.auth.CreateUser(request)

    def ActivateUser(self, request, context):
        logger.info("ActivateUser request received")
        return self.auth.ActivateUser(request)

    def DeactivateUser(self, request, context):
        logger.info("DeactivateUser request received")
        return self.auth.DeactivateUser(request)

    def ValidateToken(self, request, context):
        logger.info("ValidateToken request received")
        return self.auth.ValidateToken(request)

    def BlacklistToken(self, request, context):
        logger.info("BlacklistToken request received")
        return self.auth.BlacklistToken(request)


server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

authenticator_pb2_grpc.add_AuthenticatorServicer_to_server(
    AuthenticatorServicer(), server)

print('Starting server. Listening on port 50051.')
server.add_insecure_port('[::]:50051')
server.start()

try:
    while True:
        time.sleep(86400)
except KeyboardInterrupt:
    server.stop(0)
