/*
+-------------------------------------------------------------------------+
| OpenPGP.js implemented in Roundcube.                                    |
|                                                                         |
| This program is free software; you can redistribute it and/or modify    |
| it under the terms of the GNU General Public License version 2          |
| as published by the Free Software Foundation.                           |
|                                                                         |
| This program is distributed in the hope that it will be useful,         |
| but WITHOUT ANY WARRANTY; without even the implied warranty of          |
| MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
| GNU General Public License for more details.                            |
|                                                                         |
| You should have received a copy of the GNU General Public License along |
| with this program; if not, write to the Free Software Foundation, Inc., |
| 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.             |
|                                                                         |
+-------------------------------------------------------------------------+
| Author: Niklas Femerstrand <nik@qnrq.se>                                |
+-------------------------------------------------------------------------+
*/

// TODO: Use HTML5 web workers for heavy calculations
if(window.rcmail)
{
	rcmail.addEventListener('init', function(evt)
	{
		openpgp.init();
		openpgp.config.config.keyserver = "pgp.mit.edu:11371";
		rcmail.addEventListener('plugin.somecallback', some_callback_function);
		rcmail.addEventListener('plugin.pks_search', pks_search_callback);

		this.passphrase = $.cookie("passphrase");
		// TODO: Add key list and let user select which key to use to support multiple keys
		var key_select = "<div id='openpgpjs_key_select'>" +
						 	"<p><strong>Passphrase:</strong> <input type='password' id='passphrase' /></p>" +
							"<p><input type='checkbox' id='openpgpjs_rememberpass' /> Remember for 5 minutes</p>" +
							"<p><input type='button' class='button' value='OK' onclick='set_passphrase($(\"#passphrase\").val());' /></p>"
						"</div>";
		$("body").append(key_select);
		$("#openpgpjs_key_select" ).dialog({ modal: true,
		                                     autoOpen: false,
		                                     title: "OpenPGP key select",
		                                     width: "30%" });

		if (rcmail.env.action === 'compose')
		{
			// Spawn temp(?) ui
			var key_manager = "<div id='openpgpjs_key_manager'><div id='openpgpjs_key_manager_container'>" +
					  "<div id='openpgpjs_tabs'>" + 
					  	"<ul>" +
							"<li><a href='#openpgpjs-tab1'>Generate keys</a></li>" +
							"<li><a href='#openpgpjs-tab2'>Private keys</a></li>" + 
							"<li><a href='#openpgpjs-tab3'>Public keys</a></li>" +
						"</ul>" + 
						"<div id='openpgpjs-tab1'>" +
							"<p><strong>Passphrase:</strong> <input type='password' id='gen_passphrase' /> " +
							"<strong>Verify:</strong> <input type='password' id='gen_passphrase_verify' /> " +
							"<strong>Bits:</strong> <select id='gen_bits'><option value='1024'>1024</option><option value='2048'>2048</option><option value='4096'>4096</option></select> " +
//							"<strong>Algorithm:</strong> <select id='gen_algo'><option value='1'>RSA</option><option value='16'>DSA/Elgamal</option></select> " +
							"<input type='button' class='button' value='Generate' onclick='generate_keypair($(\"#gen_bits\").val(), 1);' />" +
							"<input type='button' class='button hidden' id='import_button' value='Import' onclick='importGenerated();' />" +
						"<div id='generated_keys'></div>" +
					"</div>" +
					"<div id='openpgpjs-tab2'>" + 
						"<table id='openpgpjs_privkeys' class='openpgpjs_keys'></table>" +
						"<div id='openpgpjs_import'>" +
							"<p><textarea id='importPrivkeyField'></textarea></p>" +
							"<p><strong>Passphrase:</strong> <input type='password' id='passphrase' /></p>" +
							"<p><input type='button' class='button' value='Import private key' onclick='importPrivKey($(\"#importPrivkeyField\").val(), $(\"#passphrase\").val());' /></p>" +
						"</div>" +
					"</div>" +
					"<div id='openpgpjs-tab3'>" +
						"<table id='openpgpjs_pubkeys' class='openpgpjs_keys'></table>" +
						"<div id='openpgpjs_import'>" +
							"<p id='openpgpjs_keyserver'></p>" +
							"<p><strong>Search:</strong> <input type='text' id='pubkey_search' onchange='pubkey_search($(this).val(), \"index\")' /></p>" +
							"<div id='openpgpjs_search_results' class='hidden'></div>" +
							"<p><textarea id='importPubkeyField'></textarea></p>" +
							"<p><input type='checkbox' checked='checked' id='openpgpjs_use_keyserver' /> Send to keyserver</p>" +
							"<p><input type='button' class='button' value='Import public key' onclick='importPubKey($(\"#importPubkeyField\").val());' /></p>" +
						"</div>" +
					"</div>" +
				  "</div></div></div>";

			$("body").append(key_manager);
			$('#openpgpjs_tabs').tabs();
			$('#openpgpjs_key_manager').dialog({ modal: true,
			                                     autoOpen: false,
			                                     title: "OpenPGP key management",
			                                     width: "90%" });
			update_tables();

			rcmail.enable_command("send", false);
			$('#rcmbtn114').click(function() { encryptAndSend(); });

			$("#mailtoolbar").prepend("<a href='#' class='button' id='openpgp_js' onclick='$(\"#openpgpjs_key_manager\").dialog(\"open\");'></a>");
			$("#composebuttons").prepend("<input id='openpgpjs_encrypt' type='checkbox' checked='checked' /> Encrypt <input id='openpgpjs_sign' checked='checked' type='checkbox' /> Sign");
		} else if (rcmail.env.action === 'show')
		{
			decrypt($('#messagebody div.message-part pre').html());
		}
	});

	function some_callback_function(response)
	{
		alert(response.message);
	}

	function generate_keypair(bits, algo)
	{
		if($('#gen_passphrase').val() == '')
		{
			alert("Please specify a passphrase!");
			return;
		} else if($("#gen_passphrase").val() != $("#gen_passphrase_verify").val())
		{
			alert("Passphrase mismatch.");
			return;
		}

		var keys = openpgp.generate_key_pair(algo, bits, $("#_from option[value='" + $('#_from option:selected').val() + "']").text(), $('#gen_passphrase').val()); 
		$('#generated_keys').html("<pre id='generated_private'>" + keys.privateKeyArmored + "</pre><pre id='generated_public'>" + keys.publicKeyArmored  +  "</pre>");
		$('#import_button').removeClass("hidden");
	}

	function importGenerated()
	{
		$('#import_button').addClass("hidden");
		try
		{
			importPubKey($("#generated_public").html());
			importPrivKey($("#generated_private").html(), $("#gen_passphrase").val());
			alert("Great success! Please save your keys somewhere safe, preferably in an encrypted container. Our servers can't see your keys.");
			$("#gen_passphrase").val("");
			$("#gen_passphrase_verify").val("");

		}
		catch(Exception)
		{
			// Errors come from other functions
			return;
		}
	}

	// TODO: Detect which private key we're using. Depends on multiple key support in key selector.
	function set_passphrase(p)
	{
		this.passphrase = p;
		if($('#messagebody div.message-part pre').length > 0)
		{
			var r = decrypt($('#messagebody div.message-part pre').html());
		}
		else
		{
			var r = true;
			encryptAndSend(); // Async
		}

		// TODO: Detect idle time, and store for 5 minutes idle time instead of just straight 5 minutes
		if(r != false && $('#openpgpjs_rememberpass').is(':checked'))
		{
			// 5*60*1000ms
			var date = new Date();
			date.setTime(date.getTime() + (5*60*1000));
			$.cookie("passphrase", p, { expires: date });
		}
		$('#openpgpjs_key_select').dialog('close');
	}
	
	function encryptAndSend()
	{
		if($("#openpgpjs_encrypt").is(':checked'))
		{
			if(passphrase == null && openpgp.keyring.privateKeys.length > 0)
			{
				$("#openpgpjs_key_select").dialog('open');
				return;
			} else if(openpgp.keyring.privateKeys.length === 0 || openpgp.keyring.publicKeys.length === 0)
			{
				alert("Please generate or import keys in the OpenPGP key manager!");
				return;
			}

			var pubkeys = new Array();
			// TODO Move to key_select set_passphrase()
			var keyid = openpgp.keyring.privateKeys[0].obj.getKeyId();
			var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
			var priv_key = openpgp.read_privateKey(privkey_armored);

			var recipients = $("#_to").val().split(",");

			for (var i = 0; i < recipients.length; i++)
			{
				var recipient = recipients[i].replace(/(.+?<)/, '').replace(/>/, '');
				var pubkey = openpgp.keyring.getPublicKeyForAddress(recipient);
				pubkeys.push(pubkey[0].obj);
			}

			// TODO sign
			$("textarea#composebody").val(openpgp.write_encrypted_message(pubkeys, $("textarea#composebody").val()));
		}

		rcmail.enable_command("send", true);
		return rcmail.command('send','',this,event);
	}

	function importPubKey(key)
	{
		try
		{
			openpgp.keyring.importPublicKey(key);
			openpgp.keyring.store();
			update_tables();
			$('#importPubkeyField').val("");
		}
		catch(e)
		{
			alert("Could not import public key, possibly wrong format.");
			return;
		}
	}


	function pubkey_search(val, op)
	{
		if(val.length > 1)
			rcmail.http_post('plugin.pks_search', 'search=' + val + '&op=' + op);
	}

	function pks_search_callback(response)
	{
		if(response.op === "index")
		{
			var results = "";
			var rows = response.message.split("\n");
			for(var i = 0; i < rows.length; i++)
			{
				var split = rows[i].split(":");
				if(split[0] != '')
					results += "<div id='" + split[0] + "' class='search_row" + (i%2 != 0 ? " odd" : "") + "' onclick='pubkey_search(this.id, \"get\");'>" + split[1] + "</div>";
			}
			if(results != '')
			{
				$("#openpgpjs_search_results").removeClass("hidden");
				$("#openpgpjs_search_results").html(results);
			}
		}
		else if(response.op === "get")
		{
			var parsed = "";
			var rows   = response.message.split("\n");
			for(var i = 0; i < rows.length; i++)
			{
				if(rows[i] === "-----BEGIN PGP PUBLIC KEY BLOCK-----")
					var parse = true;
				if(parse === true)
					parsed += rows[i] + "\n";
				// For some stupid fucking JavaScript bullshit reason this statement is
				// never true unless done this way.
				if(rows[i].match(/-----END PGP PUBLIC KEY BLOCK-----/))
					var parse = false;
			}
			$("#importPubkeyField").html(parsed);
		}
	}

	function importPrivKey(key, passphrase)
	{
		if(passphrase === '')
		{
			alert('Please enter passphrase.');
			return;
		}

		// Verify passphrase
		try
		{
			// TODO: Verify passphrase by testing encryption
		}
		catch(e)
		{
			alert('Wrong passphrase specified');
			return false;
		}
		
		try
		{
			openpgp.keyring.importPrivateKey(key, passphrase);
			openpgp.keyring.store();
			update_tables();
			$('#importPrivkeyField').val("");
			$('#passphrase').val("");
		}
		catch(e)
		{
			//alert("Could not import private key, possibly wrong format.");
			return;
		}
	}
	
	function update_tables()
	{
		$('#openpgpjs_pubkeys').empty();
		$('#openpgpjs_pubkeys').append("<tr class='boxtitle'><th>Key ID</th><th>Fingerprint</th><th>Person</th><th>Length/Alg.</th><th>Status</th><th>Action</th></tr>");

		for (var i = 0; i < openpgp.keyring.publicKeys.length; i++)
		{
			var status = openpgp.keyring.publicKeys[i].obj.verifyBasicSignatures();
			var result = "<tr class='key' onclick='displayPub(" + i + ");'><td>0x" +
				     util.hexstrdump(openpgp.keyring.publicKeys[i].obj.getKeyId()).toUpperCase().substring(8) +
				     "</td><td>" + 
                     util.hexstrdump(openpgp.keyring.publicKeys[i].obj.getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ") +
				     "</td><td>" +
				     escapeHtml(openpgp.keyring.publicKeys[i].obj.userIds[0].text) +
				     "</td><td>" +
				     getAlgorithmString(openpgp.keyring.publicKeys[i].obj) +
				     "</td><td>" +
				     (status ? "Valid" : "Invalid") + 
				     "</td><td>" +
				     "<a href='#' onclick='openpgp.keyring.removePublicKey(" + i + "); update_tables();'>Delete</a>" +
				     "</td></tr>";
			$('#openpgpjs_pubkeys').append(result);
		}
		
		$('#openpgpjs_privkeys').empty();
		// TODO: Add length/alg info and status. Requires patching openpgpjs.
		// When this is finished, write a function like getAlgorithmString() for private keys.
		$('#openpgpjs_privkeys').append("<tr class='boxtitle'><th>Key ID</th><th>Fingerprint</th><th>Person</th><!-- <th>Length/Alg.</th><th>Status</th> --><th>Action</th></tr>");
		
		for (var i = 0; i < openpgp.keyring.privateKeys.length; i++)
		{
			for (var j = 0; j < openpgp.keyring.privateKeys[i].obj.userIds.length; j++)
			{
				$("#openpgpjs_privkeys").append("<tr class='key' onclick='displayPriv(" + i + ");'><td>0x" +
				util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getKeyId()).toUpperCase().substring(8) +
				"</td><td>" +
                util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ") +
				"</td><td>" +
				escapeHtml(openpgp.keyring.privateKeys[i].obj.userIds[j].text) +
//				"</td><td>" +
//				"</td><td>" +
				"</td><td>" +
				"<a href='#' onclick='openpgp.keyring.removePrivateKey(" + i + "); update_tables();'>Delete</a>" +
				"</td></tr>");
			}
		}

		$('#openpgpjs_keyserver').html("<strong>Keyserver:</strong> " + openpgp.config.config.keyserver);
	}

	function displayPub(key)
	{
		$("#importPubkeyField").val(openpgp.keyring.publicKeys[key].armored);
	}

	function displayPriv(key)
	{
		var keyid = openpgp.keyring.privateKeys[key].obj.getKeyId();
		$("#importPrivkeyField").val(openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored);
	}

	function getAlgorithmString(publicKey)
	{
		var result = publicKey.publicKeyPacket.MPIs[0].mpiByteLength * 8 + "/";
		switch (publicKey.publicKeyPacket.publicKeyAlgorithm)
		{
			case 1:
				result += "RSA(S/E)";
				break;
			case 2:
				result += "RSA(E)";
				break;
			case 3:
				result += "RSA(S)";
				break;
			case 16:
				result += "Elg";
				break;
			case 17:
				result += "DSA";
				break;
		}

		return result;
	}
	
	// TODO: Add signature verification, depends on key ring connection
	function decrypt(data)
	{
		var msg = openpgp.read_message(data);
		
		if(!msg)
			return;

		// TODO
		// if(openpgp.keyring.privateKeys.length === 0)
		// 	open keymanager
		if(this.passphrase === 'undefined' || this.passphrase == null && openpgp.keyring.privateKeys.length > 0)
		{
			$("#openpgpjs_key_select").dialog('open');
			return;
		}

		// TODO debug
		if(openpgp.keyring.privateKeys.length < 1)
			return;

		// TODO Move to key_select set_passphrase()
		var keyid = openpgp.keyring.privateKeys[0].obj.getKeyId();
		var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
		var priv_key = openpgp.read_privateKey(privkey_armored);
		var keymat = null;
		var sesskey = null;
		
		for (var i = 0; i< msg[0].sessionKeys.length; i++)
		{
			if (priv_key[0].privateKeyPacket.publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes)
			{
				keymat = { key: priv_key[0], keymaterial: priv_key[0].privateKeyPacket};
				sesskey = msg[0].sessionKeys[i];
				break;
			}

			for (var j = 0; j < priv_key[0].subKeys.length; j++)
			{
				if (priv_key[0].subKeys[j].publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes)
				{
					keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
					sesskey = msg[0].sessionKeys[i];
					break;
				}
			}
		}

		if (keymat != null)
		{
			if (!keymat.keymaterial.decryptSecretMPIs(passphrase))
			{
				alert("Passphrase for secrect key was incorrect!");
				$("#openpgpjs_key_select").dialog('open');
				return false;
			}

			$('#messagebody div.message-part pre').html("<strong>********* *BEGIN ENCRYPTED or SIGNED PART* *********</strong><br />" + escapeHtml(msg[0].decrypt(keymat, sesskey)) + "<br /><strong>********** *END ENCRYPTED or SIGNED PART* **********</strong>");
		} else {
			alert("No private key found!");
		}
	}

	function escapeHtml(unsafe)
	{
			  return unsafe
			        .replace(/&/g, "&amp;")
					.replace(/</g, "&lt;")
					.replace(/>/g, "&gt;")
					.replace(/"/g, "&quot;")
			        .replace(/'/g, "&#039;");
	}
	
	function showMessages(msg) { console.log(msg); }
}
