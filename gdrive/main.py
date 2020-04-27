#!/usr/bin/python3
#-*- coding:utf-8 -*-

import os
import flask
import requests
import json
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from pathlib import Path
from mst.cmds import attest_command, verify_command, info_command, fetch_command
from helpers import *
#client_config, GFiles, Record

SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v3'

app = flask.Flask('mainstay_gdrive')
app.secret_key = os.getenv('APP_SECRET_KEY')

@app.route('/', methods=['GET', 'POST'])
def home():
    if 'credentials' not in flask.session:
      return flask.render_template("home.html")

    credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

    if credentials_to_dict(credentials)['refresh_token'] == None:
        clear_credentials()
        return flask.redirect(flask.url_for('home'))

    drive = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials,
        cache_discovery=False)

    flask.session['credentials'] = credentials_to_dict(credentials)

    gfiles = main_logic(drive)

    if flask.request.method == 'POST':
        checksums_operations()
        attest()

    return flask.render_template('loggedin.html', gfiles = gfiles)

def main_logic(drive):
    mainstay_folder_id = search_mainstay_folder(drive)
    if mainstay_folder_id == "MainStay folder not found. Please create.":
        gfiles = mainstay_folder_id
    else:
        gfiles = search_mainstay_files(drive, mainstay_folder_id)
        gfiles = GFiles(gfiles)

    return gfiles

def search_mainstay_folder(drive):
    results = drive.files().list(
        q="mimeType = 'application/vnd.google-apps.folder'",
        fields ="files(name, id)").execute()
    items = results.get('files', [])

    if not items:
        folder_id = "MainStay folder not found. Please create."
    else:
        for item in items:
            if 'mainstay' in item['name'].lower():
                folder_id = item.get('id')

    return folder_id

def search_mainstay_files(drive, mainstay_folder_id):
    qstring=f"'{mainstay_folder_id}' in parents"
    results = drive.files().list(
        spaces='drive',
        q=qstring,
        fields = "files(name, md5Checksum, id, size)").execute()
    items = results.get('files', [])

    if not items:
        gfiles = "No files found in folder."
    else:
        gfiles = []
        for item in items:
            name = item['name']
            checksum = item.get('md5Checksum', 'no checksum')
            size = item.get('size', '-')
            temp = {'name': name, 'checksum': checksum, 'size': size}
            gfiles.append(temp)

    return gfiles

def checksums_operations():
    if flask.request.form['checksums']:
        posted_checksums = flask.request.form['checksums'].split()
        print(posted_checksums)

        return posted_checksums

    if flask.request.form['checksums_verify']:
        verified_checksums = flask.request.form['checksums_verify']
        print(verified_checksums)

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

@app.route('/test')
def test_api_request():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

  drive = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)

  files = drive.files().list().execute()

  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.jsonify(**files)

@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

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

  #return flask.redirect(flask.url_for('home'))

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
    args.service_url = 'https://mainstay.xyz'
    args.bitcoin_node = 'https://api.blockcypher.com/v1/btc/main/txs/'
    try:
        args.slot = flask.request.form['slot']
        args.api_token = flask.request.form['api_token']
        args.commitment = flask.request.form['commitment']
    except KeyError as ke:
        flask.flash('Something went wrong')


    attrs = vars(args)
    print(', '.join("%s: %s" % item for item in attrs.items()))
    result = attest_command(args)
    print(result)
    if result == False:
        flask.flash('Something went wrong')

    return json.dumps(result)

@app.route('/verify', methods=['POST'])
def verify():
	args = Record()
	args.service_url = 'https://mainstay.xyz'
	args.bitcoin_node = 'https://api.blockcypher.com/v1/btc/main/txs/'
	try:
		args.slot = int(request.form['slot'])
		args.api_token = request.form['api_token']
		args.commitment = request.form['commitment']
	except KeyError as ke:
		abort(400)

	result = verify_command(args)
	return json.dumps(result)


@app.route('/info', methods=['POST'])
def info():
	args = Record()
	args.service_url = 'https://mainstay.xyz'
	args.bitcoin_node = 'https://api.blockcypher.com/v1/btc/main/txs/'
	try:
		args.slot = int(request.form['slot'])
		args.api_token = request.form['api_token']
	except KeyError as ke:
		abort(400)
	
	result = info_command(args)
	if result == False:
		abort(422)
	
	return result


@app.route('/fetch', methods=['POST'])
def fetch():
	args = Record()
	args.service_url = 'https://mainstay.xyz'
	args.bitcoin_node = 'https://api.blockcypher.com/v1/btc/main/txs/'
	try:
		args.slot = int(request.form['slot'])
		args.api_token = request.form['api_token']
		args.commitment = request.form['commitment']
	except KeyError as ke:
		abort(400)
	
	args.save_object = None
	result = fetch_command(args)
	if result == False:
		abort(422)
	
	return json.dumps(args.save_object, indent=2, sort_keys=True), 200, mime_text


if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(host='0.0.0.0', debug=True)
