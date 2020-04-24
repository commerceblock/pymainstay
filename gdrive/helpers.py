import os
from flask_table import Table, Col

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

client_config = {
  "web": {
    "client_id": GOOGLE_CLIENT_ID,
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://accounts.google.com/o/oauth2/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": GOOGLE_CLIENT_SECRET,
    "redirect_uris": [
        'http://localhost:5000'
    ],
    "javascript_origins": [
        'https://files.mainstay.xyz'
    ]
  }
}

class GFiles(Table):
    name = Col('Name')
    checksum = Col('Checksum')
    size = Col('Size')

class Record:
    def __getattr__(self, attr):
        return None
