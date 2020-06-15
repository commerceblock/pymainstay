import hashlib
import os

DROPBOX_API_KEY = os.getenv('DROPBOX_API_KEY')
DROPBOX_CLIENT_ID = os.getenv('DROPBOX_CLIENT_ID')
DROPBOX_CLIENT_SECRET = os.getenv('DROPBOX_CLIENT_SECRET')

AUTHORITY = 'https://www.dropbox.com'
AUTHORIZE_ENDPOINT = '/oauth2/authorize'

authorize_url = f"{AUTHORITY}{AUTHORIZE_ENDPOINT}"


def combine_hashes(hashes):
    hashes_wo_space = "".join(hashes)
    combined = hashlib.sha256(hashes_wo_space.encode('utf-8')).hexdigest()
    return combined


class Record:
    def __getattr__(self, attr):
        return None
