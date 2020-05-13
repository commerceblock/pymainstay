import hashlib
from flask_table import Table, Col


MICROSOFT_CLIENT_ID = '0b2a4858-b7e7-4b15-a2ad-6da23d866dfe'
MICROSOFT_CLIENT_SECRET = 'cJSPE06=+$ieehvdPNG980$'
AUTHORITY = 'https://login.microsoftonline.com/common'
AUTHORIZE_ENDPOINT = '/oauth2/v2.0/authorize'
SCOPES = 'openid profile offline_access user.read calendars.read'
TOKEN_ENDPOINT = '/oauth2/v2.0/token'

authorize_url = f"{AUTHORITY}{AUTHORIZE_ENDPOINT}"
token_url = f"{AUTHORITY}{TOKEN_ENDPOINT}"
graph_url = 'https://graph.microsoft.com/v1.0'


class GFiles(Table):
    name = Col('Name')
    checksum = Col('Checksum')
    size = Col('Size')


class Record:
    def __getattr__(self, attr):
        return None


def combine_hashes(string):
    hashes_wo_space = "".join(string.split())
    combined = hashlib.sha256(hashes_wo_space.encode('utf-8')).hexdigest()
    return combined
