#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###############################################################################
# This HTTPD acts bridge to make OpenPGP functionality accessible for         #
# JavaScript through locally installed GnuPG binaries and keyrings.           #
#                                                                             #
# Copyright (C) Niklas Femerstrand <nik@qnrq.se>                              #
#                                                                             #
# This program is free software; you can redistribute it and/or modify it     #
# under the terms of the GNU General Public License version 2 as published by #
# the Free Software Foundation.                                               #
#                                                                             #
# This program is distributed in the hope that it will be useful, but WITHOUT #
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or       #
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for    #
# more details.                                                               #
#                                                                             #
# You should have received a copy of the GNU General Public License along     #
# with this program; if not, write to the Free Software Foundation, Inc.,     #
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.                 #
###############################################################################
# iM4G1N3 A FR33 W0RLD Wh3R3 0n3 W0uLDN'T N33D K0P1R19H7 2 S4Y N0 2 K0PiFi9H7 #
###############################################################################

import socket, ssl, sys, gnupg, json
from os.path import expanduser
import urllib.parse
import http.server
from socketserver import ThreadingMixIn

home = expanduser("~")
home += "/.gnupg/"
gpg = gnupg.GPG(gnupghome = home)
gpg.encoding = "utf-8"


# Main request handler, called from PyGPGRequestHandler.do_GET()
def handle_request(request_handler):
	#print("HTTP request headers:\n" + request_handler.headers.as_string())

	allow_request = ""
	response = ""

	origin = request_handler.headers.get("Origin")
	origin_hostname = origin.replace("http://", "").replace("https://", "")
	if origin_hostname not in cors:
		response = "Illegal origin"
	else:
		allow_request = 1
		# Read as many bytes from the input stream as the "Content-length" header tells us to.
		# This (and the payload parsing) could be replaced by cgi.FieldStorage.
		cmdstr = request_handler.rfile.read(int(request_handler.headers.get("Content-length"))).decode("utf-8")
		print("HTTP request body:\n" + cmdstr)
		if(cmdstr.strip()):
			response = do_gpg(cmdstr)
		else:
			response = "No HTTP body received."
			print(response)

	if allow_request:
		request_handler.send_response(200)
		request_handler.send_header("Access-Control-Allow-Origin", origin)
	else:
		request_handler.send_error(403)

	request_handler.send_header("Server", "pygpghttpd")
	request_handler.end_headers()
	try:
		request_handler.wfile.write(response.encode())
	except:
		request_handler.wfile.write(response)

def do_gpg(cmdstr):
	c       = {}
	cmds_ok = ["keygen", "keylist", "keydel", "keyexport", "keyimport", "encrypt", "decrypt", "sign", "verify"]

	c = dict(urllib.parse.parse_qsl(cmdstr))

	if "cmd" not in c:
		return("Missing cmdstr for GPG op")

	for cmd_ok in cmds_ok:
		if cmd_ok == c["cmd"]:
			return(globals()[c["cmd"]](c))

	return("Unsupported cmdstr")

def keylist(cmd):
	if "private" not in cmd:
		cmd["private"] = False
	else:
		if cmd["private"] == "true" or cmd["private"] == "1":
			cmd["private"] = True
		else:
			cmd["private"] = False

	keys = gpg.list_keys(cmd["private"])
	return(json.dumps(keys))

def keygen(cmd):
	required    = ["type", "length", "name", "email", "passphrase"]
	key_types   = ["RSA", "DSA"]
	key_lengths = ["2048", "4096"]

	for req in required:
		if req not in cmd:
			return("Insufficient parameters: %s" % (req))

	if cmd["type"] not in key_types:
		return("Incorrect: type")

	if cmd["length"] not in key_lengths:
		return("Incorrect: length")

	input_data = gpg.gen_key_input(key_type = cmd["type"], key_length = cmd["length"], name_real = cmd["name"], name_email = cmd["email"], passphrase = cmd["passphrase"], name_comment = "pygpghttpd")
	key = gpg.gen_key(input_data)

	if key:
		return("1")
	return("0")

def keydel(cmd):
	if "private" not in cmd:
		cmd["private"] = False
	else:
		if cmd["private"] == "true" or cmd["private"] == "1":
			cmd["private"] = True
		else:
			cmd["private"] = False

	if "fingerprint" not in cmd:
		return("Insufficient parameters: fingerprint")

	return(str(gpg.delete_keys(cmd["fingerprint"], cmd["private"])))

# Allow only pubkey export for security
def keyexport(cmd):
	if "id" not in cmd:
		return("Insufficient parameters: id")

	return(gpg.export_keys(cmd["id"]))

def keyimport(cmd):
	if "key" not in cmd:
		return("Insufficient parameters: key")

	return(gpg.import_keys(cmd["key"]))

def encrypt(cmd):
	required = ["data", "recipients"]

	for req in required:
		if req not in cmd:
			return("Insufficient parameters: %s" % (req))

	try:
		cmd["sign"]
	except:
		cmd["sign"] = None
		cmd["passphrase"] = None
		pass
	else:
		if "passphrase" not in cmd:
			return("Insufficient parameters: passphrase (needed since sign is set)")

	encrypted = gpg.encrypt(cmd["data"], recipients = cmd["recipients"], sign = cmd["sign"], passphrase = cmd["passphrase"])
	print(encrypted.stderr)
	if(not encrypted):
		return("Encryption failed. Check recipient address and pass phrase, if applicable.")
	else:
		return(str(encrypted))

def decrypt(cmd):
	required = ["data", "passphrase"]

	for req in required:
		if req not in cmd:
			return("Insufficient parameters: %s" % (req))

	decrypted = gpg.decrypt(message = cmd["data"], passphrase = cmd["passphrase"])
	print(decrypted.stderr)

	# Currently there seems to be no way of telling whether a signature was valid or not because decrypted.ok
	# is always True as long as the decryption was successful. So we have to look at gnupg's output to detect a
	# verification failure.
	if(decrypted.stderr.find('ERRSIG') > -1):
		return("Signature verification failed!");
	if(not decrypted):
		return("Decryption failed. Incorrect pass phrase or problem with private key.");
	else:
		return(decrypted.data)

def sign(cmd):
	required = ["data", "keyid", "passphrase"]

	for req in required:
		if req not in cmd:
			return("Insufficient parameters: %s" % (req))

	signed = gpg.sign(cmd["data"], keyid = cmd["keyid"], passphrase = cmd["passphrase"]);
	if(not signed):
		return("Signing failed. Check your pass phrase and private key.");
	else:
		return(str(signed))

def verify(cmd):
	if "data" not in cmd:
		return("Insufficient parameters: data")

	return(str(bool(gpg.verify(cmd["data"]))))



# Custom handler used for each new HTTP request
class PyGPGRequestHandler(http.server.BaseHTTPRequestHandler):
	def do_GET(self):
		print("HTTP connection from %s" % (self.client_address[0]))
		handle_request(self)

	do_POST = do_GET


# Subclass to have HTTP requests be processed in separate threads
class ThreadedHTTPServer(ThreadingMixIn, http.server.HTTPServer): pass


# Read allowed hostnames from text file
cors = []
f = open("accepted_domains.txt", 'r')
for line in f:
	if not line.startswith("#"):
		cors.append(line.strip())

# Setup http server
server_address = ('127.0.0.1', 11337)
httpd = ThreadedHTTPServer(server_address, PyGPGRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
				 server_side = True,
				 certfile = "./cert.pem",
				 keyfile = "./cert.pem",
				 ssl_version = ssl.PROTOCOL_SSLv23)
try:
	httpd.serve_forever()
except:
	print("Failed to start httpd!")

