#!/usr/bin/env python3

import json
import os
import time
import flask
from authlib.integrations.requests_client import OAuth2Session
from helpers import (MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET,
                     SCOPES, graph_url, authorize_url, token_url,
                     OFiles, Record, combine_hashes, get_user,
                     get_folder_id_item, get_folder_id_created,
                     get_files_list)
from mst.cmds import attest_command, verify_command

import datetime

app = flask.Flask('mainstay_onedrive')
app.secret_key = os.getenv('APP_SECRET_KEY')


@app.route('/', methods=['GET', 'POST'])
def home():
    if 'credentials' not in flask.session:
        flask.flash('Please login first', 'primary')
        return flask.render_template("login.html")

    credentials = get_token()
    ofiles = main_logic(credentials)
    commitment = None

    return flask.render_template('index.html', ofiles=ofiles,
                                 commitment=commitment)


def main_logic(credentials):
    search_mainstay_folder(credentials)
    ofiles = search_mainstay_files(credentials)
    if not ofiles:
        return []
    else:
        ofiles = OFiles(ofiles)

    for file in ofiles.items:
        file['extension'] = file.get('name').split('.')[-1]
        if file['size'] != '-':
            file['size'] = round(int(file.get('size')) / (1024 * 1024), 2)

        try:
            file['modifiedTime'] = datetime.datetime.strptime(file['modifiedTime'], '%Y-%m-%dT%H:%M:%S.%fZ')
        except ValueError:
            file['modifiedTime'] = datetime.datetime.strptime(file['modifiedTime'], '%Y-%m-%dT%H:%M:%SZ')
        finally:
            file['modifiedTime'] = None

    return ofiles


def initialize_context():
    context = {}
    context['user'] = flask.session.get('user', {'is_authenticated': False})

    return context


def search_mainstay_folder(credentials):
    graph_client = OAuth2Session(token=credentials)
    graph_path = '/me/drive/root:/Mainstay'
    response = graph_client.get(f"{graph_url}{graph_path}").json()

    folder_id = get_folder_id_item(response)
    if folder_id:
        pass
    else:
        folder_id = create_mainstay_folder(credentials)

    return folder_id


def create_mainstay_folder(credentials):
    graph_client = OAuth2Session(token=credentials)
    graph_path = '/me/drive/root/children'
    headers = {'Content-Type': 'application/json'}
    file_metadata = {
        'name': 'Mainstay',
        'folder': {},
        '@microsoft.graph.conflictBehavior': 'fail'
    }

    response = graph_client.post(f"{graph_url}{graph_path}",
                                 json=file_metadata, headers=headers).json()

    folder_id = get_folder_id_created(response)

    return folder_id


def search_mainstay_files(credentials):
    graph_client = OAuth2Session(token=credentials)
    graph_path = '/me/drive/root:/Mainstay:/children'
    response = graph_client.get(f"{graph_url}{graph_path}").json()
    ofiles = get_files_list(response)

    return ofiles


@app.route('/get_commitment', methods=['POST'])
def get_commitment():
    try:
        posted_checksums = flask.request.get_json().get('checksums')
        processed_checksums = combine_hashes(posted_checksums)
        return processed_checksums
    except:
        return Response()


def checksums_operations():
    if flask.request.form['checksums']:
        posted_checksums = flask.request.form['checksums']
        processed_checksums = combine_hashes(posted_checksums)

        return processed_checksums

    if flask.request.form['checksums_verify']:
        verified_checksums = flask.request.form['checksums_verify']

        return verified_checksums


@app.route('/authorize')
def authorize():
    redirect_uri = flask.url_for('oauth2callback', _external=True)
    flow = OAuth2Session(client_id=MICROSOFT_CLIENT_ID,
                         scope=SCOPES,
                         redirect_uri=redirect_uri)

    authorization_url, state = flow.create_authorization_url(
        authorize_url,
        access_type='online',
        prompt='login',
        include_granted_scopes='true')

    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    state = flask.session['state']
    redirect_uri = flask.url_for('oauth2callback', _external=True)
    flow = OAuth2Session(client_id=MICROSOFT_CLIENT_ID,
                         scope=SCOPES,
                         state=state,
                         redirect_uri=redirect_uri)

    authorization_response = flask.request.url

    token_params = {
        'client_secret': MICROSOFT_CLIENT_SECRET,
        'authorization_response': authorization_response,
    }

    credentials = flow.fetch_token(token_url, **token_params)
    store_token(credentials)
    store_user(credentials)

    return flask.redirect(flask.url_for('home'))


def store_token(credentials):
    flask.session['credentials'] = credentials


def store_user(credentials):
    user = get_user(credentials)
    flask.session['user'] = {
        'is_authenticated': True,
        'name': user['displayName'],
        'email': user['mail'] if (user['mail'] is not None)
        else user['userPrincipalName']
    }


def get_token():
    credentials = flask.session['credentials']
    redirect_uri = flask.url_for('oauth2callback', _external=True)
    if credentials is not None:
        now = time.time()
        expire_time = credentials['expires_at'] - 300
        if now >= expire_time:
            flow = OAuth2Session(client_id=MICROSOFT_CLIENT_ID,
                                 client_secret=MICROSOFT_CLIENT_SECRET,
                                 token=credentials,
                                 scope=SCOPES,
                                 redirect_uri=redirect_uri)

            new_token = flow.refresh_token(token_url)
            store_token(new_token)
            store_user(new_token)
            credentials = new_token

        return credentials
    else:
        return credentials


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    else:
        flask.flash('Please login first', 'primary')

    return flask.render_template("login.html")


@app.route('/about')
def about():
    return flask.render_template("about.html")


@app.route('/attest', methods=['POST'])
def attest():
    args = Record()
    args.addition = 1
    args.service_url = 'https://mainstay.xyz'
    args.bitcoin_node = 'https://api.blockcypher.com/v1/btc/main/txs/'

    data = flask.request.get_json()
    try:
        args.slot = data.get('slotNumber')
        args.api_token = data.get('apiKey')
        if not data.get('commitment'):
            flask.flash('Please input commitment', 'warning')
            args.commitment = "None"
        else:
            args.commitment = data.get('commitment')
    except KeyError as ke:
        flask.flash('Request could not be satisfied', 'dark')

    result = attest_command(args)

    response_data = {}

    if result:
        response_data['response'] = result.get('response')
        response_data['date'] = datetime.datetime.fromtimestamp(result.get('timestamp') / 1000)
        response_data['allowance'] = f"Cost: {result.get('allowance').get('cost')}"

    if result == False:
        flask.flash('Request could not be satisfied', 'dark')

    return response_data


@app.route('/verify', methods=['POST'])
def verify():
    args = Record()
    args.service_url = 'https://mainstay.xyz'
    args.bitcoin_node = 'https://api.blockcypher.com/v1/btc/main/txs/'

    data = flask.request.get_json()

    slot_number = data.get('slotNumber')
    try:
        args.slot = int(slot_number) if slot_number else -1
    except:
        return json.dumps({"Error": "Please input right slot number"})

    args.commitment = data.get('commitment')

    response_data = {}

    result = verify_command(args)

    if result:
        if ('confirmed' in result and not result.get('confirmed')) or not result[0]:
            response_data['commitment'] = 'Not confirmed'
        else:
            response_data['commitment'] = args.commitment
            response_data['slot'] = args.slot
            response_data['txid'] = result[1].split()[8]
            response_data['bitcoin_block'] = result[2].split()[3]
            response_data['height'] = result[2].split()[5]
            response_data['date'] = str(datetime.datetime.strptime(result[2].split()[7], '%Y-%m-%dT%H:%M:%SZ'))
        return response_data
    else:
        response_data['commitment'] = "Unknown"

    return response_data


@app.route('/.well-known/microsoft-identity-association.json', methods=['GET'])
def well_known():
    SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
    json_url = os.path.join(SITE_ROOT, ".well-known", "microsoft-identity-association.json")
    data = json.load(open(json_url))
    return data


if __name__ == '__main__':
    app.run(host='0.0.0.0', ssl_context='adhoc', debug=False)
