#!/usr/bin/python3
# -*- coding:utf-8 -*-

import os
import flask
import requests
import json
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import datetime
import maya
from pathlib import Path

from flask import Response

from mst.cmds import attest_command, verify_command, info_command, fetch_command
from helpers import *

app = flask.Flask('mainstay_gdrive')
app.secret_key = os.getenv('APP_SECRET_KEY')


@app.route('/', methods=['GET', 'POST'])
def home():
    if 'credentials' not in flask.session:
        return flask.render_template("login.html")

    credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])

    drive = googleapiclient.discovery.build(
        API_SERVICE_NAME,
        API_VERSION,
        credentials=credentials,
        cache_discovery=False
    )

    flask.session['credentials'] = credentials_to_dict(credentials)

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

    gfiles = main_logic(drive)

    vars = {
        'gcid': GOOGLE_CLIENT_ID,
        'gcappid': GOOGLE_APP_ID,
        'gcbrowserkey': GOOGLE_DEVELOPER_KEY,
        'gcfolderid': os.getenv('GOOGLE_FOLDER_ID')
    }

    return flask.render_template('index.html', gfiles=gfiles, commitment=commitment, vars=vars)


def main_logic(drive):
    mainstay_folder_id = search_mainstay_folder(drive)
    gfiles = search_mainstay_files(drive, mainstay_folder_id)
    if gfiles == "No authorized files found in folder.":
        return []
    else:
        gfiles = GFiles(gfiles)

    for file in gfiles.items:
        file['extension'] = file.get('name').split('.')[-1]
        if file['size'] != '-':
            file['size'] = round(int(file.get('size')) / (1024 * 1024), 2)

        dt = maya.parse(gfiles.items[0].get('modifiedTime')).datetime()
        file['modifiedTime'] = f"{dt.date()} {dt.time()} {dt.tzinfo}"

    return gfiles


def search_mainstay_folder(drive):
    results = drive.files().list(
        q="mimeType = 'application/vnd.google-apps.folder' and trashed=false",
        fields="files(name, id)").execute()
    items = results.get('files', [])

    if not items:
        flask.flash('MainStay folder not found. Creating.', 'warning')
        folder_id = create_mainstay_folder(drive)
    else:
        for item in items:
            if 'mainstay' in item['name'].lower():
                folder_id = item.get('id')
                os.environ['GOOGLE_FOLDER_ID'] = folder_id

    return folder_id


def create_mainstay_folder(drive):
    file_metadata = {
        'name': 'MainStay',
        'mimeType': 'application/vnd.google-apps.folder'
    }
    file = drive.files().create(body=file_metadata,
                                fields='id').execute()
    folder_id = file.get('id')

    return folder_id


def search_mainstay_files(drive, mainstay_folder_id):
    qstring = f"'{mainstay_folder_id}' in parents and trashed=false"
    results = drive.files().list(
        spaces='drive',
        q=qstring,
        fields="files(name, md5Checksum, id, size, modifiedTime)").execute()
    items = results.get('files', [])

    if not items:
        gfiles = "No authorized files found in folder."
        flask.flash(gfiles, 'warning')
    else:
        gfiles = []
        for item in items:
            name = item['name']
            checksum = item.get('md5Checksum', 'no checksum')
            size = item.get('size', '-')
            modifiedTime = item.get('modifiedTime', '-')
            temp = {
                'name': name,
                'checksum': checksum,
                'size': size,
                'modifiedTime': modifiedTime}
            gfiles.append(temp)

    return gfiles


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


@app.route('/about')
def about():
    return flask.render_template("about.html")


@app.route('/authorize')
def authorize():
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config,
        scopes=SCOPES
    )

    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent',
        include_granted_scopes='true')

    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config,
        scopes=None,
        state=state
    )

    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect(flask.url_for('home'))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        flask.flash('You have to be loggedin first.', 'warning')
        return flask.redirect(flask.url_for('home'))

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post('https://oauth2.googleapis.com/revoke',
                           params={'token': credentials.token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})

    clear_credentials()

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return flask.redirect(flask.url_for('home'))
    else:
        return flask.redirect(flask.url_for('home'))


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


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
        if 'error' in result and result.get('error') == 'your merkle root is unknown to us':
            response_data['commitment'] = "Make it Unknown"
        elif 'confirmed' in result and not result.get('confirmed'):
            response_data['commitment'] = 'Not confirmed'
        else:
            response_data['commitment'] = args.commitment
            response_data['slot'] = args.slot
            response_data['txid'] = result[1].split()[8]
            response_data['bitcoin_block'] = result[2].split()[3]
            response_data['height'] = result[2].split()[5]
        return json.dumps(response_data)
    else:
        response_data['commitment'] = "Unknown"

    return response_data


if __name__ == '__main__':
    app.run(host='0.0.0.0', ssl_context='adhoc', debug=False)
