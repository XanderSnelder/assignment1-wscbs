import unittest
from helper_modules.auth_helpers import hash_password, is_password_strong, is_username_valid, PASSWORD_SECRET, base64url_encode, base64url_decode, jwt_decode, jwt_encode, generate_jwt_token
import hashlib
import base64
import hmac
from datetime import datetime, timedelta, timezone
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

# Set expiration date JWT_token
DAYS_EXPIRE = 1

class TestAuthHelperFunctions(unittest.TestCase):

    def test_is_password_strong(self):

        """
        Test if the is_password_strong method correctly identifies strong and weak passwords.
        """

        strong_passwords = [
            "P@$$w0rd!",
            "Str0ng_P@ssw0rd!",
            "S3cureP@$$123"
        ]

        weak_passwords = [
            "password",
            "P@ssword",
            "pass123",
            "p@ssword"
        ]

        # Test strong passwords
        for password in strong_passwords:
            self.assertTrue(is_password_strong(password), f"The password '{password}' identified as strong.")

        # Test weak passwords
        for password in weak_passwords:
            self.assertFalse(is_password_strong(password), f"The password '{password}' identified as weak.")

    def test_is_username_valid(self):

        """
        Test if the is_username_valid method correctly identifies valid and invalid usernames.
        """

        valid_usernames = [
            "user_123",
            "abcde",
            "UserName",
            "valid_1"
        ]

        invalid_usernames = [
            "user",
            "user name",
            "user@domain.com",
            "user!",
            "abc",
            "!"
        ]

        # Test valid usernames
        for username in valid_usernames:
            self.assertTrue(is_username_valid(username), f"The username '{username}' is valid.")

        # Test invalid usernames
        for username in invalid_usernames:
            self.assertFalse(is_username_valid(username), f"The username '{username}' is invalid.")

    def test_hash_password(self):

        """
        Test if the hash_password method accurately hashes the given password using sha256.
        """

        password = "Str0ng_P@ssw0rd!"
        expected_hash = hmac.new(PASSWORD_SECRET.encode('utf-8'), password.encode('utf-8'), hashlib.sha256).hexdigest()
        hashed_password = hash_password(password)

        self.assertEqual(hashed_password, expected_hash, "The hashed password should match the expected hash.")

    def test_generate_jwt_token(self):

        """
        Test if the generate_jwt_token method correctly generated a JWT_token.
        """

        username = 'testuser'
        role = 'regular'
        secret_key = PASSWORD_SECRET

        # Generate a JWT token using the generate_jwt_token function
        token = generate_jwt_token(username, role, secret_key)

        # Decode the generated JWT token
        decoded_payload = jwt_decode(token, secret_key)

        # Verify if the decoded payload contains the expected information
        self.assertEqual(decoded_payload['sub'], username, "The subject should be the username")
        self.assertEqual(decoded_payload['role'], role, "The role should be the user's role")

        # Verify that the decoded payload contains the 'exp' key (expiration time)
        self.assertIn('exp', decoded_payload, "The decoded payload should contain the 'exp' key")

        # Verify that the expiration time is set correctly
        tolerance = 5 # Allow for a tolerance of 5 seconds, since there might be a slight delay between token generation and decoding
        expected_expiration = int((datetime.now(timezone.utc) + timedelta(days=DAYS_EXPIRE)).timestamp())
        self.assertTrue(abs(decoded_payload['exp'] - expected_expiration) <= tolerance, "The expiration time should be set one day in the future")
    
    def test_base64url_encode(self):

        """
        Test if method correctly encodes data using base64.
        """

        # Create a bytes object to encode and to be tested
        data = b'data to test'  

        # Generate expected result using urlsafe_b64encode() to encode data, remove any trailing equal signs
        expected_encoded_data = base64.urlsafe_b64encode(data).rstrip(b'=')

        # Execute the function to be tested
        encoded_data = base64url_encode(data)  

        self.assertEqual(encoded_data, expected_encoded_data) 

    def test_base64url_decode(self):

        """
        Test if method correctly decodes data using base64.
        """

        # Create a bytes object to encode and to be tested
        data = b'data to test'  

        # Generate the encoded data
        encoded_data = base64.urlsafe_b64encode(data).rstrip(b'=')

        # Generate the expected decoded data
        expected_decoded_data = base64.urlsafe_b64decode(encoded_data + b'=' * (4 - len(encoded_data) % 4))

        # Call the function which we test
        decoded_data = base64url_decode(encoded_data)  

        self.assertEqual(decoded_data, expected_decoded_data)

    def test_jwt_encode_decode_valid(self):

        """
        Test if both methods with a valid secret successfully encodes/decodes a JWT.
        """
        
        header = {"typ": "JWT", "alg": "HS256"} # JWT header
        payload = {"user_id": 1, "role": "admin"} # JWT payload
        secret = "my_secret_key" # Secret for encoding and decoding

        token = jwt_encode(header, payload, secret) # Execute method to generate token
        decoded_payload = jwt_decode(token, secret) # Execute method to decode generated token

        # Assert decoded payload is not None and matches original payload
        self.assertIsNotNone(decoded_payload)
        self.assertEqual(decoded_payload, payload)

    def test_jwt_encode_decode_invalid(self):

        """"
        Test if both methods with a invalid secret unsuccessfully encodes/decodes a JWT.
        """

        header = {"typ": "JWT", "alg": "HS256"} # JWT header
        payload = {"user_id": 1, "role": "admin"} # JWT payload
        secret = "my_secret_key" # Valid secret for encoding and decoding
        invalid_secret = "invalid_secret_key" # Invalid secret for decoding

        token = jwt_encode(header, payload, secret)  # Execute method to generate the token
        decoded_payload = jwt_decode(token, invalid_secret) # Execute method to decode the token with invalid secret

        # Assert decoded payload is None because invalid secret
        self.assertIsNone(decoded_payload)

if __name__ == '__main__':
    unittest.main()
