import json
import secrets
import string
import getpass

import grpc

from pb import authenticator_pb2
from pb import authenticator_pb2_grpc


SERVER_ADDRESS = "localhost:50051"


def check_status(test_name, response, expected="OK"):
    actual = response.StatusCode
    passed = actual == expected

    print(
        f"[{'PASS' if passed else 'FAIL'}] {test_name}: "
        f"expected={expected}, received={actual}"
    )

    if not passed:
        raise AssertionError(
            f"{test_name} failed: expected {expected}, got {actual}"
        )

    return response


def random_username():
    suffix = "".join(
        secrets.choice(string.ascii_lowercase + string.digits)
        for _ in range(8)
    )
    return f"test_user_{suffix}"


def main():
    print(f"Connecting to {SERVER_ADDRESS}...\n")

    channel = grpc.insecure_channel(SERVER_ADDRESS)
    grpc.channel_ready_future(channel).result(timeout=10)

    stub = authenticator_pb2_grpc.AuthenticatorStub(channel)

    try:
        print("1. Login")

        admin_username = "Admin" # input("Administrator username: ").strip()
        admin_password = "password" # getpass.getpass("Administrator password: ")

        admin_response = stub.Login(
            authenticator_pb2.LoginRequest(
                username=admin_username,
                password=admin_password,
            )
        )

        check_status("Administrator login", admin_response)

        admin_token = admin_response.token
        assert admin_token, "Login returned an empty token"

        print("\n2. ListingUsers")

        listing_response = stub.Listing(
            authenticator_pb2.ListingRequest(
                token=admin_token,
            )
        )

        check_status("List users", listing_response)

        users = json.loads(listing_response.list)
        print(f"Found {len(users)} user(s):")

        for user in users:
            print(
                f"  username={user['username']}, "
                f"role={user['role']}, "
                f"active={user['is_active']}"
            )

        print("\n3. CreateUser")

        username = random_username()
        user_password = secrets.token_urlsafe(16)

        create_response = stub.CreateUser(
            authenticator_pb2.CreateUserRequest(
                token=admin_token,
                username=username,
                role="maintainer",
            )
        )

        check_status("Create test user", create_response)

        print(f"Created username: {username}")

        print("\n4. ActivateUser")

        activate_response = stub.ActivateUser(
            authenticator_pb2.ActivateUserRequest(
                username=username,
                password=user_password,
            )
        )

        check_status("Activate test user", activate_response)

        print("\n5. Login as test user")

        user_login_response = stub.Login(
            authenticator_pb2.LoginRequest(
                username=username,
                password=user_password,
            )
        )

        check_status("Test user login", user_login_response)


        user_token = user_login_response.token
        assert user_token, "Login returned an empty token"

        print("\n6. ValidateToken")

        validate_response = stub.ValidateToken(
            authenticator_pb2.ValidateTokenRequest(
                token=user_token,
            )
        )

        check_status("Validate test user token", validate_response)

        print(f"Subject: {validate_response.sub}")
        print(f"Role: {validate_response.role}")

        assert validate_response.role == "maintainer"

        print("\n7. Authorization check")

        denied_response = stub.Listing(
            authenticator_pb2.ListingRequest(
                token=user_token,
            )
        )

        check_status(
            "Maintainer denied listing",
            denied_response,
            expected="PERMISSION_DENIED",
        )

        user_login_response = stub.Login(
            authenticator_pb2.LoginRequest(
                username=username,
                password=user_password,
            )
        )

        check_status("Test user login", user_login_response)

        user_token = user_login_response.token

        print("\n8. BlacklistToken")

        blacklist_response = stub.DeleteToken(
            authenticator_pb2.DeleteTokenRequest(
                token=user_token,
            )
        )


        check_status("Blacklist test user token", blacklist_response)

        print("\n9. Validate revoked token")

        revoked_response = stub.ValidateToken(
            authenticator_pb2.ValidateTokenRequest(
                token=user_token,
            )
        )

        check_status(
            "Revoked token rejected",
            revoked_response,
            expected="UNAUTHENTICATED",
        )

        print("\n10. DeactivateUser")

        deactivate_response = stub.DeactivateUser(
            authenticator_pb2.DeactivateUserRequest(
                token=admin_token,
                username=username,
            )
        )

        check_status("Deactivate test user", deactivate_response)

        print("\n11. Login after deactivation")

        deactivated_login = stub.Login(
            authenticator_pb2.LoginRequest(
                username=username,
                password=user_password,
            )
        )

        check_status(
            "Deactivated user login rejected",
            deactivated_login,
            expected="UNAUTHENTICATED",
        )

        print("\nAll tests passed!")

    except grpc.FutureTimeoutError:
        print(
            "Could not connect to the server. "
            "Make sure server.py is running."
        )

    except grpc.RpcError as exc:
        print(f"gRPC error: {exc.code().name}: {exc.details()}")

    except AssertionError as exc:
        print(f"\nTEST FAILED: {exc}")

    finally:
        channel.close()


if __name__ == "__main__":
    main()
