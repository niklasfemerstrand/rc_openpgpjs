#!/usr/bin/env python
# -*- coding: utf-8 -*-
###############################################################################
# This HTTPD acts bridge to make OpenPGP functionality accessible for         #
# JavaScript through locally installed GnuPG binaries and keyrings.           #
# pygpghttpd is originally a part of the rc_openpgpjs project which           #
# adds OpenPGP functionality to the Roundcube webmail client through the      #
# OpenPGP.js library. pygpghttpd should be considered a separate project that #
# grows out of rc_openpgpjs simulaneously as rc_openpgpjs gets support for    #
# multiple drivers.                                                           #
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
# iM4G1N3 a FR33 W0RLD Wh3R3 0n3 W0uLDN'T N33D K0P1R19H7 2 S4Y N0 2 K0PiFi9H7 #
###############################################################################
# openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout cert.pem
#
# curl -i -k --data "cmd=keygen&key_type=RSA&key_length=2048&name_real=realname&name_email=email" -H "Origin: https://localhost" https://localhost:11337/
#
# NOTE: In order for Internet Explorer to work with this httpd it must have TLSv1.1 and TLSv1.2 enabled.
# This is set in Internet Options -> Advanced, or HKEY_CURRENT_USER\Software\Classes\Local Settings\MuiCache\

import re, socket, ssl, sys, gnupg
import _thread as thread

gpg = gnupg.GPG(gnupghome="./.gpg")
gpg.encoding = "utf-8"

def deal_with_client(connstream):
	data = connstream.recv(1024).decode("utf-8")
	m = re.search("^(GET|POST)", data)
	if not m:
		data += connstream.recv(1024).decode("utf-8")

	while data:
		dd      = data.split("\n")
		cmdstr  = ""
		origin  = ""
		referer = ""

		for header in dd:
			print(header)
			m = re.search("^Origin: (.*)$", header)
			if m:
				origin = m.groups()[0].rstrip("\n").rstrip("\r")

			# Fetch domain from referer header, some browsers always provide origin.
			m = re.search("^Referer: (.*)/login", header)
			if m:
				referer = m.groups()[0].rstrip("\n").rstrip("\r")

			if "=" in header and "&" in header:
				cmdstr = header

		# Fall back on referer
		if not origin:
			origin = referer

		if not do_something(connstream, data, origin, cmdstr):
			break

def do_something(connstream, data, origin, cmdstr):
	allow_request = ""
	response = ""

	cors = []
	with open("accepted_domains.txt", 'r') as f:
		lines = f.readlines()
		for line in lines:
			if not line.startswith("#"):
				cors.append(line.replace("\r", "").replace("\n", ""))

	o = origin.replace("http://", "").replace("https://", "")
	if o not in cors:
		response = "Illegal origin"
	else:
		allow_request = 1
		print("NOW TREAT CMDSTR")
		response = "allowed"

	content_length = str(len(response))

	if allow_request:
		connstream.write("HTTP/1.1 200 OK\r\n".encode())
	else:
		connstream.write("HTTP/1.1 403 Forbidden\r\n".encode())
	connstream.write(("Content-Length: " + content_length + "\r\n").encode())
	connstream.write("Content-Type: text/html\r\n".encode())
	connstream.write("Server: PyGPG HTTPD bridge by qnrq\r\n".encode())

	if allow_request:
		connstream.write(("Access-Control-Allow-Origin: " + origin + "\r\n").encode())
	connstream.write("\r\n".encode())
	connstream.write(response.encode())

def threadHandler(client, addr):
	connstream = ""

	try:
		connstream = ssl.wrap_socket(client,
									 server_side = True,
									 certfile = "./cert.pem",
									 keyfile = "./cert.pem",
									 ssl_version = ssl.PROTOCOL_SSLv23)
	except Exception as exception:
		print(exception)

	if not connstream:
		return
	try:
		deal_with_client(connstream)
	finally:
		connstream.shutdown(socket.SHUT_RDWR)

try:
	sock = socket.socket(socket.AF_INET)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(("localhost", 11337))
	sock.listen(5)
except socket.error:
	print("Failed to create socket")
	sys.exit()

while True:
	client, addr = sock.accept()
	thread.start_new_thread(threadHandler, (client, addr))
