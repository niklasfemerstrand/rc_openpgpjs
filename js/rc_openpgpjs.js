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
//		openpgp.config.debug = true
		rcmail.addEventListener('plugin.pks_search', pks_search_callback);
//		rcmail.enable_command("savedraft", false);

		this.passphrase = $.cookie("passphrase");
		var key_select = "<div id='openpgpjs_key_select'>" +
							"<div id='openpgpjs_key_select_list'></div>" +
						 	"<p><strong>" + rcmail.gettext('passphrase', 'rc_openpgpjs') + ":</strong> <input type='password' id='passphrase' /></p>" +
							"<p><input type='checkbox' id='openpgpjs_rememberpass' /> Remember for 5 minutes</p>" +
							"<p><input type='button' class='button' value='OK' onclick='set_passphrase($(\"#openpgpjs_selected_id\").val(), $(\"#passphrase\").val());' /></p>"
						"</div>";
		$("body").append(key_select);
		$("#openpgpjs_key_select" ).dialog({ modal: true,
		                                     autoOpen: false,
		                                     title: "OpenPGP key select",
		                                     width: "30%",
		                                     open: function(event, ui) {
		                                            	update_tables();
		                                           }
		                                   });
			$('#openpgpjs_tabs').tabs();
			$('#openpgpjs_key_manager').dialog({ modal: true,
			                                     autoOpen: false,
			                                     title: rcmail.gettext('key_management', 'rc_openpgpjs'),
			                                     width: "90%" });
			update_tables();

		if (rcmail.env.action === "compose" || rcmail.env.action === "preview")
		{
			rcmail.enable_command("send", false);
			$('#rcmbtn114').click(function() { encryptAndSend(); });

			$("#mailtoolbar").prepend("<a href='#' class='button' id='openpgp_js' onclick='$(\"#openpgpjs_key_manager\").dialog(\"open\");'></a>");
			$("#composebuttons").prepend("<input id='openpgpjs_encrypt' type='checkbox' checked='checked' /> Encrypt <input id='openpgpjs_sign' checked='checked' type='checkbox' /> Sign");
		} else if (rcmail.env.action === 'show')
		{
			$("#rcmbtn111").after("<a href='#' class='button' id='openpgp_js' onclick='$(\"#openpgpjs_key_manager\").dialog(\"open\");'></a>");
			decrypt($('#messagebody div.message-part pre').html());
		}
	});

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
		// TODO Currently only RSA is supported, fix this when OpenPGP.js implements ElGamal & DSA
		var keys = openpgp.generate_key_pair(1, bits, $("#_from option[value='" + $('#_from option:selected').val() + "']").text(), $('#gen_passphrase').val());
		$('#generated_keys').html("<pre id='generated_private'>" + keys.privateKeyArmored + "</pre><pre id='generated_public'>" + keys.publicKeyArmored  +  "</pre>");
		$('#import_button').removeClass("hidden");
	}

	function importGenerated()
	{
		$('#import_button').addClass("hidden");
		importPubKey($("#generated_public").html());

		if(importPrivKey($("#generated_private").html(), $("#gen_passphrase").val()))
			alert("Great success! Please save your keys somewhere safe, preferably in an encrypted container. Keys are not transferred to the server.");

		$("#gen_passphrase").val("");
		$("#gen_passphrase_verify").val("");
	}

	/*
	 * Params:
	 * 	i: int, used as openpgp.keyring[private|public]Keys[i]
	 * 	p: str, the passphrase
	 */
	function set_passphrase(i, p)
	{
		if(i === "-1")
		{
			alert("Please select a key.");
			return false;
		}

		if(!openpgp.keyring.privateKeys[i].obj.decryptSecretMPIs(p))
		{
			alert("Incorrect passphrase.");
			return false;
		}

		this.passphrase = JSON.stringify({ "id" : i, "passphrase" : p } );

		if($('#messagebody div.message-part pre').length > 0)
		{
			if(!decrypt($('#messagebody div.message-part pre').html()))
				return false;
		} else {
			if(!encryptAndSend())
				return false;
		}

		// TODO: Detect idle time, and store for 5 minutes idle time instead of just straight 5 minutes
		if($('#openpgpjs_rememberpass').is(':checked'))
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
		if($("#openpgpjs_encrypt").is(":checked") && $("#openpgpjs_sign").is(":checked"))
		{
			if(passphrase == null && openpgp.keyring.privateKeys.length > 0)
			{
				$("#openpgpjs_key_select").dialog('open');
				return false;
			} else if(openpgp.keyring.privateKeys.length === 0 || openpgp.keyring.publicKeys.length === 0)
			{
				alert("Please generate or import keys in the OpenPGP key manager!");
				return false;
			}

			// json string from set_passphrase, obj.id = privkey id, obj.passphrase = privkey passphrase
			passobj = JSON.parse(passphrase);
			var pubkeys = new Array();
			var keyid = openpgp.keyring.privateKeys[passobj.id].obj.getKeyId();
			var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
			var priv_key = openpgp.read_privateKey(privkey_armored);

			var recipients = $("#_to").val().split(",");

			for (var i = 0; i < recipients.length; i++)
			{
				var recipient = recipients[i].replace(/(.+?<)/, '').replace(/>/, '');
				var pubkey = openpgp.keyring.getPublicKeyForAddress(recipient);
				pubkeys.push(pubkey[0].obj);
				// TODO: For some reason signing can only be made with one pubkey, gotta investigate
				break;
			}

			// TODO: For some reason signing can only be made with one pubkey, gotta investigate
			$("textarea#composebody").val(openpgp.write_signed_and_encrypted_message(priv_key[0], pubkey[0].obj, $("textarea#composebody").val()));
			return;
		} else if($("#openpgpjs_encrypt").is(":checked") && $("#openpgpjs_sign").not(":checked")) {
			var pubkeys = new Array();
			var recipients = $("#_to").val().split(",");

			for (var i = 0; i < recipients.length; i++)
			{
				var recipient = recipients[i].replace(/(.+?<)/, '').replace(/>/, '');
				var pubkey = openpgp.keyring.getPublicKeyForAddress(recipient);
				pubkeys.push(pubkey[0].obj);
			}

			$("textarea#composebody").val(openpgp.write_encrypted_message(pubkeys, $("textarea#composebody").val()));
		} else if($("#openpgpjs_encrypt").not(":checked") && $("#openpgpjs_sign").is(":checked")) {
			if(passphrase == null && openpgp.keyring.privateKeys.length > 0)
			{
				$("#openpgpjs_key_select").dialog('open');
				return false;
			} else if(openpgp.keyring.privateKeys.length === 0 || openpgp.keyring.publicKeys.length === 0)
			{
				alert("Please generate or import keys in the OpenPGP key manager!");
				return false;
			}

			passobj = JSON.parse(passphrase);
			var pubkeys = new Array();
			var keyid = openpgp.keyring.privateKeys[passobj.id].obj.getKeyId();
			var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
			var priv_key = openpgp.read_privateKey(privkey_armored);

			if(!priv_key[0].decryptSecretMPIs(passobj.passphrase))
				alert("wrong pass");

			$("textarea#composebody").val(openpgp.write_signed_message(priv_key[0], $("textarea#composebody").val()));
		}

		rcmail.enable_command("send", true);
		return rcmail.command('send', '', this,event);
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
			return false;
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
			return false;
		}

		try
		{
			privkey_obj = openpgp.read_privateKey(key)[0];
		}
		catch(e)
		{
			alert("Wrong key format.");
			return false;
		}

		if(!privkey_obj.decryptSecretMPIs(passphrase))
		{
			alert('Wrong passphrase specified');
			return false;
		}

		openpgp.keyring.importPrivateKey(key, passphrase);
		openpgp.keyring.store();
		update_tables();
		$('#importPrivkeyField').val("");
		$('#passphrase').val("");

		return true;
	}

	// Param i: int, used as openpgp.keyring[private|public]Keys[i]
	function select_key(i)
	{
		fingerprint = "0x" + util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getKeyId()).toUpperCase().substring(8);
		$("#openpgpjs_selected").html("<strong>Selected:</strong> " + fingerprint);
		$("#openpgpjs_selected_id").val(i);
		$("#passphrase").val("");
	}
	
	// TODO: This function is _really_ messy and ugly, refactor it when it's proven functional. Especially the fingerprint part...
	function update_tables()
	{
		// Fills key_select key list
		$("#openpgpjs_key_select_list").html("<input type=\"hidden\" id=\"openpgpjs_selected_id\" value=\"-1\" />");

		// Only one key in keyring, nothing to select from
		if(openpgp.keyring.privateKeys.length == 1)
		{
			$("#openpgpjs_selected_id").val(0);
		} else {
			// Selected set as $("#openpgpjs_selected_id").val(), then get that value from set_passphrase
			for (var i = 0; i < openpgp.keyring.privateKeys.length; i++)
			{
				for (var j = 0; j < openpgp.keyring.privateKeys[i].obj.userIds.length; j++)
				{
					fingerprint = "0x" + util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getKeyId()).toUpperCase().substring(8);
					person = escapeHtml(openpgp.keyring.privateKeys[i].obj.userIds[j].text);
					$("#openpgpjs_key_select_list").append("<div class=\"clickme\" onclick=\"select_key(" + i + ");\">" + fingerprint + " " + person + "</div>");
				}
			}

			$("#openpgpjs_key_select_list").append("<div id=\"openpgpjs_selected\"><strong>Selected:</strong> <i>None</i></div>");
		}

		// Fills OpenPGP key manager tables
		$('#openpgpjs_pubkeys tbody').empty();

		for (var i = 0; i < openpgp.keyring.publicKeys.length; i++)
		{
			var status = openpgp.keyring.publicKeys[i].obj.verifyBasicSignatures();
			var result = "<tr class='clickme' onclick='displayPub(" + i + ");'><td>0x" +
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
				     "<a href='#' onclick='if(confirm(\"Delete this public key?\")) { openpgp.keyring.removePublicKey(" + i + "); update_tables(); }'>Delete</a>" +
				     "</td></tr>";
			$('#openpgpjs_pubkeys tbody').append(result);
		}
		
		$('#openpgpjs_privkeys tbody').empty();
		// TODO: Add length/alg info and status. Requires patching openpgpjs.
		// When this is finished, write a function like getAlgorithmString() for private keys.		
		for (var i = 0; i < openpgp.keyring.privateKeys.length; i++)
		{
			for (var j = 0; j < openpgp.keyring.privateKeys[i].obj.userIds.length; j++)
			{
				$("#openpgpjs_privkeys tbody").append("<tr class='clickme' onclick='displayPriv(" + i + ");'><td>0x" +
				util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getKeyId()).toUpperCase().substring(8) +
				"</td><td>" +
                util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ") +
				"</td><td>" +
				escapeHtml(openpgp.keyring.privateKeys[i].obj.userIds[j].text) +
//				"</td><td>" +
				"</td><td>" +
				getAlgorithmString(openpgp.keyring.privateKeys[i].obj) +
				"</td><td>" +
				"<a href='#' onclick='if(confirm(\"Delete this private key?\")) { openpgp.keyring.removePrivateKey(" + i + "); update_tables(); }'>Delete</a>" +
				"</td></tr>");
			}
		}
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

	function getAlgorithmString(key)
	{
		if(typeof(key.publicKeyPacket) != "undefined")
		{
			var result = key.publicKeyPacket.MPIs[0].mpiByteLength * 8 + "/";
			var sw = key.publicKeyPacket.publicKeyAlgorithm;
		} else {
			// For some reason publicKeyAlgorithm doesn't work directly on the privatekeyPacket, heh
			var result = (key.privateKeyPacket.publicKey.MPIs[0].mpiByteLength * 8 + "/");
			var sw = key.privateKeyPacket.publicKey.publicKeyAlgorithm;
		}

		switch(sw)
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
			return false;

		if(!("decrypt" in msg[0]))
			return false;

		// msg is only signed, so verify it
		if(!("sessionKeys" in msg[0]))
		{
			var sender = rcmail.env.sender.match(/<(.*)>$/)[1];
			var pubkey = openpgp.keyring.getPublicKeyForAddress(sender);
			// TODO: Make visually obvious
			if(msg[0].verifySignature(pubkey))
				console.log("Verified signature");
			return;
		}

		if(!openpgp.keyring.hasPrivateKey())
		{
			alert("Detected PGP encrypted content but no imported private keys. Please import your private PGP key using the OpenPGP key manager!");
			return false;
		}

		if((this.passphrase === 'undefined' || this.passphrase == null) && openpgp.keyring.privateKeys.length > 0)
		{
			$("#openpgpjs_key_select").dialog('open');
			return false;
		}

		// json string from set_passphrase, obj.id = privkey id, obj.passphrase = privkey passphrase
		passobj = JSON.parse(passphrase);

		// TODO Move to key_select set_passphrase()
		var keyid = openpgp.keyring.privateKeys[passobj.id].obj.getKeyId();
		var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
		var priv_key = openpgp.read_privateKey(privkey_armored);
		var keymat = null;
		var sesskey = null;

		if(!openpgp.keyring.privateKeys[passobj.id].obj.decryptSecretMPIs(passobj.passphrase))
		{
			alert("Passphrase for secrect key was incorrect!");
			$("#openpgpjs_key_select").dialog('open');
			return false;
		}

		// msg is encrypted
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
			try
			{
				keymat.keymaterial.decryptSecretMPIs(passobj.passphrase);
			}
			catch (e)
			{
				alert("Failed to decrypt secret MPIs");
				return false;
			}

			$('#messagebody div.message-part pre').html("<strong>********* *BEGIN ENCRYPTED or SIGNED PART* *********</strong><br />" + escapeHtml(msg[0].decrypt(keymat, sesskey)) + "<br /><strong>********** *END ENCRYPTED or SIGNED PART* **********</strong>");
			return true;
		} else {
			alert("This message was not intended for this private key.");
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
