import requests
import ssl
from datetime import datetime
import jwt
from jwt import PyJWKClient
import dotenv
import os
import certifi

# Load environment variables
loaded = dotenv.load_dotenv(".env")
if not loaded:
    print("No .env file loaded")
    raise Exception("No .env file loaded, please create one with CLIENT_SECRET")

# Constants
tenant_id = 'ea3fe077-4875-4e38-9b37-5630fdd86732'
client_id = '416154a7-89e5-41d2-9c24-541a46a6f8a0'
client_secret = os.environ.get('CLIENT_SECRET')
scope = 'api://416154a7-89e5-41d2-9c24-541a46a6f8a0/.default'
token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
jwks_url = f'https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys'
#OR
jwks__common_url = f'https://login.microsoftonline.com/common/discovery/v2.0/keys'


# Function to get an access token
def get_access_token():
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': scope,
        'grant_type': 'client_credentials'
    }
    
    response = requests.post(token_url, headers=headers, data=data)
    
    if response.status_code == 200:
        return response.json().get('access_token')
    else:
        raise Exception(f"Error fetching access token: {response.status_code}, {response.text}")

def verify_access_token(access_token):
    try:
        # Create a custom SSLContext
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        # Create a custom requests session with the SSLContext
        
        # Use PyJWKClient with the custom session
        jwk_client = PyJWKClient(jwks_url, ssl_context=ssl_context)
        signing_key = jwk_client.get_signing_key_from_jwt(access_token)
        
        # Decode and validate the token
        decoded_token = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=f"api://{client_id}",
            options={"verify_exp": True}
        )
        
        print("Token is valid")
        print(f"Issuer: {decoded_token.get('iss')}")
        print(f"Audience: {decoded_token.get('aud')}")
        print(f"Expiration: {datetime.utcfromtimestamp(decoded_token.get('exp'))}")
    
    except jwt.ExpiredSignatureError:
        raise Exception("Access token has expired")
    except Exception as e:
        raise Exception(f"Invalid token: {e}")
# Example usage
try:
    token = get_access_token()
    print(f"Access Token: {token}")
    
    verify_access_token(token)
except Exception as e:
    print(f"Error: {e}")
