import logging

logger = logging.getLogger(__name__)

def send_password_reset_email(user_email, token):
    logger.info(f"Simulating sending password reset email to {user_email} with token {token}")
    pass

def generate_reset_token(user):
    logger.info(f"Simulating generating reset token for user {user}")
    return "test_token"

def verify_reset_token(token):
    logger.info(f"Simulating verifying reset token {token}")
    # In a real scenario, this would return a user object if the token is valid
    if token == "test_token":
        # Returning a dummy object that might resemble a user for basic checks
        class DummyUser:
            def __init__(self, id):
                self.id = id
        return DummyUser(id=1) 
    return None
