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


app = flask.Flask('mainstay_onedrive')
app.secret_key = os.getenv('APP_SECRET_KEY')


@app.route('/', methods=['GET', 'POST'])
def home():
    if 'credentials' not in flask.session:
        flask.flash('Please login first', 'primary')
        return flask.render_template("home.html")

    credentials = get_token()
    ofiles = main_logic(credentials)
    commitment = None
    if flask.request.method == 'POST':
        if "post_checksums" in flask.request.form:
            if flask.request.form['checksums']:
                commitment = checksums_operations()
        if "attest" in flask.request.form:
            if flask.request.form['api_token'] and flask.request.form['slot']:
                attestation = attest()
                flask.flash(attestation, 'info')
        if "verify" in flask.request.form:
            if flask.request.form['checksums_verify']:
                commitment = checksums_operations()
                verification = verify()
                flask.flash(verification, 'info')

    return flask.render_template('loggedin.html', ofiles=ofiles,
                                 commitment=commitment)


def main_logic(credentials):
    search_mainstay_folder(credentials)
    ofiles = search_mainstay_files(credentials)
    if not ofiles:
        ofiles.append("No files found in Mainstay folder. Please add.")
    else:
        ofiles = OFiles(ofiles)

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
        'folder': { },
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


def checksums_operations():
    if flask.request.form['checksums']:
        posted_checksums = flask.request.form['checksums']
        processed_checksums = combine_hashes(posted_checksums)
        print(f"Pr_check: {processed_checksums}")
        return processed_checksums

    if flask.request.form['checksums_verify']:
        verified_checksums = flask.request.form['checksums_verify']
        print(f"Vr_check: {verified_checksums}")
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

    return flask.render_template("home.html")


@app.route('/about')
def about():
    return flask.render_template("about.html")


@app.route('/attest', methods=['POST'])
def attest():
    args = Record()
    args.service_url = 'https://mainstay.xyz'
    args.bitcoin_node = 'https://api.blockcypher.com/v1/btc/main/txs/'
    try:
        args.slot = flask.request.form['slot']
        args.api_token = flask.request.form['api_token']
        if not flask.request.form['commitment']:
            flask.flash('Please input commitment', 'warning')
            args.commitment = "None"
        else:
            args.commitment = flask.request.form['commitment']
    except KeyError as ke:
        if ke:
            flask.flash('Request could not be satisfied', 'dark')

    result = attest_command(args)
    if result is False:
        flask.flash('Request could not be satisfied', 'dark')

    return json.dumps(result)


@app.route('/verify', methods=['POST'])
def verify():
    args = Record()
    args.service_url = 'https://mainstay.xyz'
    args.bitcoin_node = 'https://api.blockcypher.com/v1/btc/main/txs/'
    try:
        if not flask.request.form['slot']:
            args.slot = -1
        else:
            args.slot = int(flask.request.form['slot'])
            args.api_token = flask.request.form['api_token']
            args.commitment = flask.request.form['checksums_verify']
    except KeyError as ke:
        if ke:
            flask.flash('Request could not be satisfied', 'dark')

    result = verify_command(args)
    return json.dumps(result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', ssl_context='adhoc', debug=True)
