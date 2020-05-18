import hashlib
import json
from flask_table import Table, Col
from authlib.integrations.requests_client import OAuth2Session

MICROSOFT_CLIENT_ID = '0b2a4858-b7e7-4b15-a2ad-6da23d866dfe'
MICROSOFT_CLIENT_SECRET = 'cJSPE06=+$ieehvdPNG980$'
AUTHORITY = 'https://login.microsoftonline.com/common'
AUTHORIZE_ENDPOINT = '/oauth2/v2.0/authorize'
SCOPES = 'openid profile offline_access user.read files.readwrite'
TOKEN_ENDPOINT = '/oauth2/v2.0/token'

authorize_url = f"{AUTHORITY}{AUTHORIZE_ENDPOINT}"
token_url = f"{AUTHORITY}{TOKEN_ENDPOINT}"
graph_url = 'https://graph.microsoft.com/v1.0'


class OFiles(Table):
    name = Col('Name')
    checksum = Col('Checksum')
    size = Col('Size')


class Record:
    def __getattr__(self, attr):
        return None


def get_user(credentials):
    graph_client = OAuth2Session(token=credentials)
    user = graph_client.get('{0}/me'.format(graph_url))

    return user.json()


def combine_hashes(string):
    hashes_wo_space = "".join(string.split())
    combined = hashlib.sha256(hashes_wo_space.encode('utf-8')).hexdigest()
    return combined


def get_folder_id_search(response):
    for k, v in response.items():
        if isinstance(v, list):
            value_list = v
            if not value_list:
                folder_id = None
            elif value_list is not None:
                list_to_string = ','.join([str(elem) for elem in value_list])
                json_parse_string = list_to_string.replace("'", "\"")
                json_object = json.loads(json_parse_string)
                if 'mainstay' in json_object['name'].lower():
                    folder_id = json_object['id']

    return folder_id


def get_folder_id_item(response):
    folder_id = response.get('id')

    return folder_id


def get_folder_id_created(response):
    if 'mainstay' in response['name'].lower():
        folder_id = response['id']
    else:
        folder_id = None

    return folder_id


def get_files_list(response):
    files_list = response.get('value')
    ofiles = []
    for v in files_list:
        name = v['name']
        size = v['size']
        checksum = v['file']['hashes']['quickXorHash']
        temp = {'name': name, 'checksum': checksum, 'size': size}
        ofiles.append(temp)

    return ofiles
