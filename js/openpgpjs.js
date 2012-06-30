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

if(window.rcmail)
{
	rcmail.addEventListener('init', function(evt)
	{
		openpgp.init();
		if (rcmail.env.action == 'compose')
		{
			// Spawn temp(?) ui
			var key_manager = "<div id='openpgpjs_key_manager' style='display:none;'>" +
					  "<div id='openpgpjs_tabs'>" + 
					  	"<ul>" +
							"<li><a href='#openpgpjs-tab1'>Private keys</a></li>" + 
							"<li><a href='#openpgpjs-tab2'>Public keys</a></li>" +
						"</ul>" + 
						"<div id='openpgpjs-tab1'>" + 
							"<table id='openpgpjs_privkeys' class='openpgpjs_keys'></table>" +
							"<div id='openpgpjs_import'>" +
								"<p><textarea id='importPrivkeyField'></textarea></p>" +
								"<p><strong>Passphrase:</strong> <input type='password' id='passphrase' /></p>" +
								"<p><input type='button' class='button' value='Import private key' onclick='importPrivKey($(\"#importPrivkeyField\").val());' /></p>" +
							"</div>" +
						"</div>" +
						"<div id='openpgpjs-tab2'>" +
							"<table id='openpgpjs_pubkeys' class='openpgpjs_keys'></table>" +
							"<div id='openpgpjs_import'>" +
								"<p><textarea id='importPubkeyField'></textarea></p>" +
								"<p><input type='button' class='button' value='Import public key' onclick='importPubKey($(\"#importPubkeyField\").val());' /></p>" +
							"</div>" +
						"</div>";

			$("body").append(key_manager);
			$('#openpgpjs_tabs').tabs();
			$("#openpgpjs_key_manager" ).dialog({ modal: true, autoOpen: true, title: "OpenPGP key management", width: "80%" });
			update_tables();

			// Disable send button before encrypt
			rcmail.enable_command("send", false);
			$('#rcmbtn110').click(function() {encryptAndSend();});
			$('#compose-buttons').append("<input type='checkbox' checked='checked' /> Encrypt <input checked='checked' type='checkbox' /> Sign");
		}
		else if(rcmail.env.action == 'show')
		{
			this.passphrase = "";
			// TODO: Add key list and let user select which key to use
			var key_select = "<div id='openpgpjs_key_select' style='display:none;'>" +
					 	"<p><strong>Passphrase:</strong> <input type='password' id='passphrase' /></p>" +
						"<p><input type='checkbox' /> Remember for this session</p>" +
						"<p><input type='button' class='button' value='OK' onclick='set_passphrase($(\"#passphrase\").val());' /></p>"
					"</div>";
			$("body").append(key_select);
			$("#openpgpjs_key_select" ).dialog({ modal: true, autoOpen: false, title: "OpenPGP key select", width: "30%" });
			decrypt($('#messageoutput').html());
		}
	});
	
	function set_passphrase(passphrase)
	{
		this.passphrase = $('#passphrase').val();
		$('#openpgpjs_key_select').dialog('close');
		decrypt($('#messageoutput').html());
	}
	
	function encryptAndSend()
	{
		//return rcmail.command('send','',this);
		alert("encrypt");
	}

	// TODO: Add to keyring	
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
	
	function importPrivKey(key)
	{
		if($('#passphrase').val() == '')
		{
			alert('Please enter passphrase.');
			return;
		}
		
		// Verify passphrase
		try
		{
			// TODO: Test encryption
		}
		catch(e)
		{
			alert('Wrong passphrase specified');
			return false;
		}
		
		try
		{
			openpgp.keyring.importPrivateKey(key, $('#passphrase').val());
			openpgp.keyring.store();
			update_tables();
			$('#importPrivkeyField').val("");
		}
		catch(e)
		{
			alert("Could not import private key, possibly wrong format.");
			return;
		}
	}
	
	function update_tables()
	{
		$('#openpgpjs_pubkeys').empty();
		$('#openpgpjs_pubkeys').append("<tr class='boxtitle'><th>Key ID</th><th>Person</th><th>Length/Alg.</th><th>Status</th><th>Action</th></tr>");

		for (var i = 0; i < openpgp.keyring.publicKeys.length; i++)
		{
			var status = openpgp.keyring.publicKeys[i].obj.verifyBasicSignatures();
			var result = "<tr><td>0x" +
				     util.hexstrdump(openpgp.keyring.publicKeys[i].obj.getKeyId()).toUpperCase().substring(8) +
				     "</td><td>" + 
				     // TODO: Sanitize this
				     openpgp.keyring.publicKeys[i].obj.userIds[0].text +
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
		// TODO: Add length/alg info, status and private key removal. Requires patching openpgpjs.
		// When this is finished, write a function like getAlgorithmString() for private keys.
		$('#openpgpjs_privkeys').append("<tr class='boxtitle'><th>Key ID</th><th>Person</th><th>Length/Alg.</th><th>Status</th><th>Action</th></tr>");
		
		for (var i = 0; i < openpgp.keyring.privateKeys.length; i++)
		{
			for (var j = 0; j < openpgp.keyring.privateKeys[i].obj.userIds.length; j++)
			{
				$("#openpgpjs_privkeys").append("<tr><td>" +
								util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getKeyId()) +
								"</td><td>" +
								// TODO: Sanitize this
								openpgp.keyring.privateKeys[i].obj.userIds[j].text +
								"</td></tr>");
			}
		}
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
	
	// TODO: Add signature verification
	function decrypt(data)
	{
		var msg = openpgp.read_message(data);
		
		if(!msg)
			return;

		if(passphrase == '')
		{
			$("#openpgpjs_key_select").dialog('open');
			return;
		}
		
		// TODO: Spawn key manager
		// else if openpgp.keyring.privateKeys.length > 1
		// Spawn key select
		if(openpgp.keyring.privateKeys.length < 1)
			return;

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
				return;
			}

			// TODO: Sanitize first
			$('#messageoutput').html("<strong>********* *BEGIN ENCRYPTED or SIGNED PART* *********</strong><br />" + msg[0].decrypt(keymat, sesskey) + "<br /><strong>********** *END ENCRYPTED or SIGNED PART* **********</strong>");
		} else {
			alert("No private key found!");
		}
	}
	
	function showMessages(msg) { console.log(msg); }
}
