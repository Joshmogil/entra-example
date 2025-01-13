scope='api://416154a7-89e5-41d2-9c24-541a46a6f8a0/App.ReadWrite.All'

import requests
import json
from datetime import datetime
import jwt
import dotenv
import os

loaded = dotenv.load_dotenv(".env")
if not loaded:
    print("No .env file loaded")
    raise Exception("No .env file loaded, please create one with CLIENT_SECRET")

# Constants - Replace with your own details
tenant_id = 'ea3fe077-4875-4e38-9b37-5630fdd86732'
client_id = '416154a7-89e5-41d2-9c24-541a46a6f8a0'
client_secret = os.environ.get('CLIENT_SECRET')
scope = 'api://416154a7-89e5-41d2-9c24-541a46a6f8a0/.default'  # Modify if you're using a different API

# URL for Microsoft Entra/AD token request
token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'

# Function to get an access token
def get_access_token():
    # Request body for client credentials grant
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': scope,
        'grant_type': 'client_credentials'
    }
    
    response = requests.post(token_url, headers=headers, data=data)
    
    if response.status_code == 200:
        access_token = response.json().get('access_token')
        return access_token
    else:
        raise Exception(f"Error fetching access token: {response.status_code}, {response.text}")

# Function to decode and validate the access token
def verify_access_token(access_token):
    try:
        # Decode the JWT token and check claims
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        
        # Check the expiration (exp) claim
        exp = decoded_token.get('exp')
        if exp:
            exp_datetime = datetime.utcfromtimestamp(exp)
            if exp_datetime < datetime.utcnow():
                raise Exception("Access token is expired")
        
        # Optionally, check issuer (iss), audience (aud), etc.
        print("Token is valid")
        print(f"Issuer: {decoded_token.get('iss')}")
        print(f"Audience: {decoded_token.get('aud')}")
        print(f"Expiration: {exp_datetime}")
        
    except jwt.ExpiredSignatureError:
        raise Exception("Access token has expired")
    except jwt.JWTError as e:
        raise Exception(f"Invalid token: {e}")

# Example usage
try:
    token = get_access_token()
    print(f"Access Token: {token}")
    
    verify_access_token(token)
    
except Exception as e:
    print(f"Error: {e}")