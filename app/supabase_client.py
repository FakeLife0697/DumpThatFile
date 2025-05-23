import json
from supabase import *
from supabase.client import Client, ClientOptions

resource = open("./resources/resources.json")
data = json.load(resource)
url: str = data["SUPABASE_URL"]
service_key: str = data["SUPABASE_PRIVATE_API"]  # Admin key
public_key: str = data["SUPABASE_PUBLIC_API"]   # Public key

def getAdminClient() -> Client:
    try:
        adminClient: Client = Client(url, service_key)
        return adminClient
    except Exception as e:
        print(f"Error establishing admin connection: {e}")
        return None

def getPublicClient() -> Client:
    try:
        publicClient: Client = Client(url, public_key,
            options = ClientOptions(
                flow_type = "pkce"
            ))
        return publicClient
    except Exception as e:
        print(f"Error establishing public connection: {e}")
        return None

def getAuthenticatedClient(access_token: str) -> Client:
    try:
        client: Client = Client(url, public_key,
            options = ClientOptions(
                flow_type = "pkce"
            ))
        client.auth.set_session(access_token)
        return client
    except Exception as e:
        print(f"Error establishing authenticated connection: {e}")
        return None