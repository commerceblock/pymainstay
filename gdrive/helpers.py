import os
import hashlib
from flask_table import Table, Col

SCOPES = ['https://www.googleapis.com/auth/drive.file']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v3'
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DEVELOPER_KEY = os.getenv('GOOGLE_DEVELOPER_KEY')
GOOGLE_APP_ID = os.getenv('GOOGLE_APP_ID')

client_config = {
  "web": {
    "client_id": GOOGLE_CLIENT_ID,
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://accounts.google.com/o/oauth2/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": GOOGLE_CLIENT_SECRET,
    "redirect_uris": [
        'https://files.mainstay.xyz'
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


def combine_hashes(hashes):
    hashes_wo_space = "".join(hashes)
    combined = hashlib.sha256(hashes_wo_space.encode('utf-8')).hexdigest()
    return combined
