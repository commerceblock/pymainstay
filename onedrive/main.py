#!/usr/bin/env python3

import json
import os
import time
import flask
from authlib.integrations.requests_client import OAuth2Session
from helpers import (MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET,
                     SCOPES, graph_url, authorize_url, token_url,
                     GFiles, Record, combine_hashes)
from mst.cmds import attest_command, verify_command


app = flask.Flask('mainstay_onedrive')
app.secret_key = os.getenv('APP_SECRET_KEY')


@app.route('/', methods=['GET', 'POST'])
def home():
    if 'credentials' not in flask.session:
        flask.flash('Please login first', 'primary')
        return flask.render_template("home.html")

    credentials = get_token()
    gfiles = get_user(credentials)
    commitment = None

    return flask.render_template('loggedin.html', gfiles=gfiles,
                                 commitment=commitment)


def get_user(credentials):
    graph_client = OAuth2Session(token=credentials)
    user = graph_client.get('{0}/me'.format(graph_url))

    return user.json()


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

    return flask.redirect(flask.url_for('home'))


def store_token(credentials):
    flask.session['credentials'] = credentials


def get_token():
    credentials = flask.session['credentials']
    redirect_uri = flask.url_for('oauth2callback', _external=True)
    if credentials is not None:
        now = time.time()
        expire_time = credentials['expires_at'] - 300
        if now >= expire_time:
            print("Am I here")
            flow = OAuth2Session(client_id=MICROSOFT_CLIENT_ID,
                                 client_secret=MICROSOFT_CLIENT_SECRET,
                                 token=credentials,
                                 scope=SCOPES,
                                 redirect_uri=redirect_uri)

            new_token = flow.refresh_token(token_url)
            store_token(new_token)
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
