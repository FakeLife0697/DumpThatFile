import json
from supabase import *
from supabase.client import Client, ClientOptions

resource = open("../resources/resources.json")
data = json.load(resource)
url: str = data["SUPABASE_URL"]
key: str = data["SUPABASE_SERVICE_KEY"]
secret: str = data["SUPABASE_CLIENT_SECRET"]

def getClient() -> None:
    supaClient = None
    try:
        supaClient: Client = Client(url, key, 
            options = ClientOptions(
                flow_type = "pkce"
            ))
        
        supaClient.auth.sign_in_with_oauth({
            "provider": "github",
            "access_token": secret, 
        })
        print("Supabase connection established")
    except Exception as e:
        print(e)
    
    return supaClient