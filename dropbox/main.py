#!/usr/bin/python3
#-*- coding:utf-8 -*-


from flask import Flask, request, abort
from pathlib import Path
import json
from mst.cmds import attest_command, verify_command, info_command, fetch_command


app = Flask('mainstay_dropbox')


mime_xhtml = [('Content-Type', 'application/xhtml+xml;charset=utf-8')]
mime_javascript = [('Content-Type', 'application/javascript;charset=utf-8'), ('Cache-Control', 'only-if-cached, max-age=604800')]
mime_python = [('Content-Type', 'application/python;charset=utf-8'), ('Cache-Control', 'only-if-cached, max-age=604800')]
mime_css = [('Content-Type', 'text/css;charset=utf-8'), ('Cache-Control', 'only-if-cached, max-age=604800')]
mime_text = [('Content-Type', 'text/plain;charset=utf-8')]
mime_json = [('Content-Type', 'application/json;charset=utf-8')]


def make_error_handler(http_error):
	@app.errorhandler(http_error)
	def error_handler(error):
		return Path(f'error.html').read_text(), http_error, mime_xhtml
	error_handler.__name__ = f'error_{http_error}'
	return error_handler

for http_error in [400, 401, 403, 404, 405, 410, 415, 422]:
	make_error_handler(http_error)


@app.route('/')
def index_html():
	return Path('index.html').read_text(), mime_xhtml


#@app.route('/favicon.ico')
#def favicon_ico():
#	return open('favicon.ico').readall()


@app.route('/style.css')
def style_css():
	return Path('style.css').read_text(), mime_css


@app.route('/brython.js')
def brython_js():
	return Path('brython.js').read_text(), mime_javascript


@app.route('/brython_stdlib.js')
def brython_stdlib_js():
	return Path('brython_stdlib.js').read_text(), mime_javascript


class Record:
	def __getattr__(self, attr):
		return None


@app.route('/attest', methods=['POST'])
def attest():
	args = Record()
	args.service_url = 'https://mainstay.xyz'
	args.bitcoin_node = 'https://api.blockcypher.com/v1/btc/main/txs/'
	try:
		args.slot = request.form['slot']
		args.api_token = request.form['api_token']
		args.commitment = request.form['commitment']
	except KeyError as ke:
		abort(400)
	
	result = attest_command(args)
	if result == False:
		abort(422)
	
	return json.dumps(result), 200, mime_json


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
	return json.dumps(result), 200, mime_json


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
	
	return result, 200, mime_json


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
	app.run(host='0.0.0.0', debug=True)

