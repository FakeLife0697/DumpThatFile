from supabase import *
from supabase.client import Client, ClientOptions

def get_user_by_email(email: str, client: Client):
    try:
        response = client.schema('public').table('users').select('*').eq('email', email).execute()
        if response.data and len(response.data) > 0:
            return response.data[0]['username']
        return None
    except Exception as e:
        print(f"Error searching user by email: {str(e)}")
        return None

def get_user_by_username(username: str, client: Client):
    try:
        response = client.schema('public').table('users').select('*').eq('username', username).execute()
        if response.data and len(response.data) > 0:
            return response.data[0]['username']
        return None
    except Exception as e:
        print(f"Error searching user by username: {str(e)}")
        return None

def get_user_public_key(username: str, client: Client):
    try:
        response = client.schema('public').table('users').select('public_key').eq('username', username).execute()
        if response.data and len(response.data) > 0:
            return response.data[0]['public_key']
        return None
    except Exception as e:
        print(f"Error getting user public key: {str(e)}")
        return None