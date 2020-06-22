import flask
from authlib.integrations.requests_client import OAuth2Session
from dropbox import Dropbox
from dropbox.exceptions import ApiError
from helpers import authorize_url, combine_hashes, Record, DROPBOX_API_KEY, DROPBOX_CLIENT_ID, DROPBOX_CLIENT_SECRET
from flask import Response
import requests
from mst.cmds import attest_command, verify_command
import datetime
import json
import os

app = flask.Flask('mainstay_dropbox')
app.secret_key = os.getenv('APP_SECRET_KEY')


@app.route('/', methods=['GET', 'POST'])
def home():
    if 'credentials' not in flask.session:
        flask.flash('Please login first', 'primary')
        return flask.render_template("login.html")

    dfiles = get_list_of_files()
    return flask.render_template('index.html', dfiles=dfiles)


@app.route('/authorize')
def authorize():
    redirect_uri = flask.url_for('oauth2callback', _external=True)
    flow = OAuth2Session(client_id=DROPBOX_CLIENT_ID, response_type='code', redirect_uri=redirect_uri)
    authorization_url, state = flow.create_authorization_url(authorize_url)
    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    redirect_uri = flask.url_for('oauth2callback', _external=True)
    token_url = "https://api.dropboxapi.com/oauth2/token"

    authorization_code = flask.request.values.get('code')
    params = {
        "code": authorization_code,
        "grant_type": "authorization_code",
        "client_id": DROPBOX_CLIENT_ID,
        "client_secret": DROPBOX_CLIENT_SECRET,
        "redirect_uri": redirect_uri
    }

    response = requests.post(token_url, data=params)
    credentials = response.json()

    store_token(credentials)

    return flask.redirect(flask.url_for('home'))


def store_token(credentials):
    flask.session['credentials'] = credentials.get('access_token')


@app.route('/revoke')
def revoke():
    if 'credentials' in flask.session:
        del flask.session['credentials']

    return flask.render_template("login.html")


@app.route('/get_commitment', methods=['POST'])
def get_commitment():
    try:
        posted_checksums = flask.request.get_json().get('checksums')
        processed_checksums = combine_hashes(posted_checksums)
        return processed_checksums
    except:
        return Response()


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
        if result.get('error'):
            response_data['response'] = result.get('error')
        else:
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
            response_data['commitment'] = str(result[1])
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


def get_list_of_files():
    get_or_create_folder()

    dbx = Dropbox(get_token())
    response = dbx.files_list_folder(path='/Mainstay')

    files = []

    for file in response.entries:
        files.append({
            'name': file.name,
            'extension': file.name.split('.')[-1],
            'size': round(int(file.size) / (1024 * 1024), 2),
            'date_modified': file.server_modified,
            'checksum': file.content_hash
        })

    return files


def get_or_create_folder():
    dbx = Dropbox(get_token())
    try:
        dbx.files_create_folder_v2('/Mainstay', autorename=False)
    except ApiError:
        pass


def get_token():
    return flask.session['credentials']


if __name__ == '__main__':
    app.run(host='0.0.0.0', ssl_context='adhoc', debug=False)
