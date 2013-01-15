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

if (window.rcmail) {
  rcmail.addEventListener('init', function (evt) {
    openpgp.init();
//  openpgp.config.debug = true
    rcmail.addEventListener('plugin.pks_search', pks_search_callback);
    rcmail.enable_command("savedraft", false);

    if (sessionStorage.length > 0) {
      this.passphrase = sessionStorage[0];
    }

    $("#openpgpjs_key_select" ).dialog({ modal: true,
                                         autoOpen: false,
                                         title: rcmail.gettext('select_key', 'rc_openpgpjs'),
                                         width: "30%",
                                         open: function(event, ui) {
                                                  updateKeySelector();
                                               }
                                       });
    $('#openpgpjs_tabs').tabs();
    $('#openpgpjs_key_manager').dialog({ modal: true,
                                         autoOpen: false,
                                         title: rcmail.gettext('key_manager', 'rc_openpgpjs'),
                                         width: "90%",
                                         open: function(event, ui) {
                                                  updateKeyManager();
                                               }
                                        });
    
    // register open-key-manager command
    rcmail.register_command('open-key-manager', function() { $("#openpgpjs_key_manager").dialog("open"); });
    rcmail.enable_command('open-key-manager', true);

    if (rcmail.env.action === "compose") {
      rcmail.addEventListener("beforesend", function(e) { if(!encryptAndSend()) return false; });
    } else if (rcmail.env.action === 'show' || rcmail.env.action === "preview") {
      decrypt($('#messagebody div.message-part pre').html());
    }
  });

  /**
   * Generates an OpenPGP key pair by calling the necessary crypto 
   * functions from openpgp.js and shows them to the user
   * 
   * @param bits {Integer} Number of bits for the key creation
   * @param algo {Integer} To indicate what type of key to make. RSA is 1
   */
  function generate_keypair(bits, algo) {
    // check if passphrase is specified
    if($('#gen_passphrase').val() == '') {
      $('#generate_key_error').removeClass("hidden");
      $('#generate_key_error p').html(rcmail.gettext('enter_pass', 'rc_openpgpjs'));
      return false;
    // check if passphrases match
    } else if($("#gen_passphrase").val() != $("#gen_passphrase_verify").val()) {
      $('#generate_key_error').removeClass("hidden");
      $('#generate_key_error p').html(rcmail.gettext('pass_mismatch', 'rc_openpgpjs'));
      return false;
    }

    //TODO: currently only RSA is supported, fix this when OpenPGP.js implements ElGamal & DSA
    // generate Openpgp key pair
    var keys = openpgp.generate_key_pair(1, bits, $("#_from option[value='" + $('#_from option:selected').val() + "']").text(), $('#gen_passphrase').val());
    
    // show key pair to user
    $('#generated_keys').html("<pre id='generated_private'>" + keys.privateKeyArmored + "</pre><pre id='generated_public'>" + keys.publicKeyArmored  +  "</pre>");
    $('#generate_key_error').addClass("hidden");
    $('#import_button').removeClass("hidden");
  }

  /**
   * Imports freshly generated key pairs into the key manager
   */
  function importGenerated() {
    $('#import_button').addClass("hidden");
    importPubKey($("#generated_public").html());

    if(importPrivKey($("#generated_private").html(), $("#gen_passphrase").val())) {
      alert(rcmail.gettext('import_gen', 'rc_openpgpjs'));
    }
    
    $("#gen_passphrase").val("");
    $("#gen_passphrase_verify").val("");
  }

  /**
   * Asks user for private key passphrass and stores passphrase with 
   * the private key is for one session if specified
   * 
   * @param i {Integer} The key id, used as openpgp.keyring.privateKeys[i]
   * @param p {String}  The corresponding passphrase
   */
  function set_passphrase(i, p) {
    // no key selected
    if(i === "-1") {
      $('#key_select_error').removeClass("hidden");
      $('#key_select_error p').html(rcmail.gettext('select_key', 'rc_openpgpjs'));
      return false;
    }

    // passphrase is incorrect
    if(!openpgp.keyring.privateKeys[i].obj.decryptSecretMPIs(p)) {
      $('#key_select_error').removeClass("hidden");
      $('#key_select_error p').html(rcmail.gettext('incorrect_pass', 'rc_openpgpjs'));
      return false;
    }

    // store passphrase with private key id as json
    this.passphrase = JSON.stringify({ "id" : i, "passphrase" : p } );
    
    // decrypt is messagebody exists
    if($('#messagebody div.message-part pre').length > 0) {
      if(!decrypt($('#messagebody div.message-part pre').html()))
        return false;
    // otherwise we are composing, so encrypt and send
    } else {
      if(!encryptAndSend())
        return false;
    }

    // store passphrase for this session
    if($('#openpgpjs_rememberpass').is(':checked')) {
      sessionStorage.setItem(i, this.passphrase);
    }
    
    $('#key_select_error').addClass("hidden");
    $('#openpgpjs_key_select').dialog('close');
  }
  
  /**
   * Encrypts and/or signs messages and sends it
   */
  function encryptAndSend() {
    // encrypt and sign message
    if($("#openpgpjs_encrypt").is(":checked") && $("#openpgpjs_sign").is(":checked")) {
      // no passphrase stored
      if(this.passphrase == null && openpgp.keyring.privateKeys.length > 0) {
        $("#openpgpjs_key_select").dialog('open');
        return false;
      // no keys imported in the key manager
      } else if(openpgp.keyring.privateKeys.length === 0 || openpgp.keyring.publicKeys.length === 0) {
        alert(rcmail.gettext('no_keys', 'rc_openpgpjs'));
        return false;
      }

      // json string from set_passphrase()
      // obj.id = private key id
      // obj.passphrase = private key passphrase
      passobj = JSON.parse(this.passphrase);

      var pubkeys = new Array();
      var keyid = openpgp.keyring.privateKeys[passobj.id].obj.getKeyId();
      var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
      var priv_key = openpgp.read_privateKey(privkey_armored);

      var recipients = $("#_to").val().split(",");

      // collect public keys of all receivers
      for (var i = 0; i < recipients.length; i++) {
        var recipient = recipients[i].replace(/(.+?<)/, '').replace(/>/, '');
        var pubkey = openpgp.keyring.getPublicKeyForAddress(recipient);
        pubkeys.push(pubkey[0].obj);
        // TODO: For some reason signing can only be made with one pubkey, gotta investigate
        break;
      }

      // TODO: For some reason signing can only be made with one pubkey, gotta investigate
      // replace original message with encrypted and signed message
      $("textarea#composebody").val(openpgp.write_signed_and_encrypted_message(priv_key[0], pubkey[0].obj, $("textarea#composebody").val()));
      
    // only encrypt message
    } else if($("#openpgpjs_encrypt").is(":checked") && $("#openpgpjs_sign").not(":checked")) {
      var pubkeys = new Array();
      var c = 0;
      var recipients = [];
      var matches = "";
      var fields = ["_to", "_cc", "_bcc"];
      var re = /[a-zA-Z0-9\._%+-]+@[a-zA-Z0-9\._%+-]+\.[a-zA-Z]{2,4}/g;
      
      // collect adresses of all receivers
      for(field in fields) {
        matches = $("#" + fields[field]).val().match(re);
        for(key in matches) {
          recipients[c] = matches[key];
          c++;
        }
      }

      // collect public keys of all receivers
      for (var i = 0; i < recipients.length; i++) {
        var recipient = recipients[i].replace(/(.+?<)/, '').replace(/>/, '');
        var pubkey = openpgp.keyring.getPublicKeyForAddress(recipient);
        pubkeys.push(pubkey[0].obj);
      }

      // replace original message with encrypted message
      $("textarea#composebody").val(openpgp.write_encrypted_message(pubkeys, $("textarea#composebody").val()));
    // only sign message
    } else if($("#openpgpjs_encrypt").not(":checked") && $("#openpgpjs_sign").is(":checked")) {
      // no passphrase stored
      if(this.passphrase == null && openpgp.keyring.privateKeys.length > 0) {
        $("#openpgpjs_key_select").dialog('open');
        return false;
      // no keys imported in the key manager
      } else if(openpgp.keyring.privateKeys.length === 0 || openpgp.keyring.publicKeys.length === 0) {
        alert(rcmail.gettext('no_keys', 'rc_openpgpjs'));
        return false;
      }

      // json string from set_passphrase()
      // obj.id = private key id
      // obj.passphrase = private key passphrase
      passobj = JSON.parse(this.passphrase);
      
      var pubkeys = new Array();
      var keyid = openpgp.keyring.privateKeys[passobj.id].obj.getKeyId();
      var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
      var priv_key = openpgp.read_privateKey(privkey_armored);

      // passphrase is incorrect
      if(!priv_key[0].decryptSecretMPIs(passobj.passphrase))
        alert(rcmail.gettext('incorrect_pass', 'rc_openpgpjs'));

      // recplace original message body with signed message
      $("textarea#composebody").val(openpgp.write_signed_message(priv_key[0], $("textarea#composebody").val()));
    }

    return true;
  }

  /**
   * Imports armored public key into the key manager
   * 
   * @param key {String} The armored public key
   */
  function importPubKey(key) {
    try {
      openpgp.keyring.importPublicKey(key);
      openpgp.keyring.store();
      updateKeyManager();
      $('#importPubkeyField').val("");
      $('#import_pub_error').addClass("hidden");
    } catch(e) {
      $('#import_pub_error').removeClass("hidden");
      $('#import_pub_error p').html(rcmail.gettext('import_failed', 'rc_openpgpjs'));
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
    } else if(response.op === "get") {
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


  /**
   * Imports armored private key into the key manager
   * 
   * @param key        {String} The armored private key
   * @param passphrase {String} The corresponding passphrase
   */
  function importPrivKey(key, passphrase) {
    // no passphrase specified
    if(passphrase === '')
    {
      $('#import_priv_error').removeClass("hidden");
      $('#import_priv_error p').html(rcmail.gettext('enter_pass', 'rc_openpgpjs'));
      return false;
    }

    // try to import private key
    try {
      privkey_obj = openpgp.read_privateKey(key)[0];
    } catch(e) {
      $('#import_priv_error').removeClass("hidden");
      $('#import_priv_error p').html(rcmail.gettext('import_failed', 'rc_openpgpjs'));
      return false;
    }

    // check if passphrase is correct
    if(!privkey_obj.decryptSecretMPIs(passphrase))  {
      $('#import_priv_error').removeClass("hidden");
      $('#import_priv_error p').html(rcmail.gettext('incorrect_pass', 'rc_openpgpjs'));
      return false;
    }

    openpgp.keyring.importPrivateKey(key, passphrase);
    openpgp.keyring.store();
    updateKeyManager();
    $('#importPrivkeyField').val("");
    $('#passphrase').val("");
    $('#import_priv_error').addClass("hidden");

    return true;
  }

  /**
   * Select a private key from the key manager
   * 
   * @param i {Integer} The key id, used as openpgp.keyring.privateKeys[i]
   */  
  function select_key(i) {
    fingerprint = "0x" + util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getKeyId()).toUpperCase().substring(8);
    $("#openpgpjs_selected").html("<strong>" + rcmail.gettext('selected', 'rc_openpgpjs') + ":</strong> " + fingerprint);
    $("#openpgpjs_selected_id").val(i);
    $("#passphrase").val("");
  }
  
  /**
   * Updates the key list for key selection
   */  
  function updateKeySelector() {
    // fill key list for key selection
    $("#openpgpjs_key_select_list").html("<input type=\"hidden\" id=\"openpgpjs_selected_id\" value=\"-1\" />");

    // only one key in keyring, nothing to select from
    if(openpgp.keyring.privateKeys.length == 1) {
      $("#openpgpjs_selected_id").val(0);
    } else {
      // Selected set as $("#openpgpjs_selected_id").val(), then get that value from set_passphrase
      for (var i = 0; i < openpgp.keyring.privateKeys.length; i++) {
        for (var j = 0; j < openpgp.keyring.privateKeys[i].obj.userIds.length; j++) {
          fingerprint = "0x" + util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getKeyId()).toUpperCase().substring(8);
          person = escapeHtml(openpgp.keyring.privateKeys[i].obj.userIds[j].text);
          $("#openpgpjs_key_select_list").append("<div class=\"clickme\" onclick=\"select_key(" + i + ");\">" + fingerprint + " " + person + "</div>");
        }
      }

      $("#openpgpjs_key_select_list").append("<div id=\"openpgpjs_selected\"><strong>" + rcmail.gettext('selected', 'rc_openpgpjs') + ":</strong> <i>" + rcmail.gettext('none', 'rc_openpgpjs') + "</i></div>");
    }
  }
  
  /**
   * Updates the public and private key tables in the key manager
   */  
  function updateKeyManager() {
    // fill key manager public key table
    $('#openpgpjs_pubkeys tbody').empty();
    for (var i = 0; i < openpgp.keyring.publicKeys.length; i++) {
      var key_id = "0x" + util.hexstrdump(openpgp.keyring.publicKeys[i].obj.getKeyId()).toUpperCase().substring(8);
      var fingerprint = util.hexstrdump(openpgp.keyring.publicKeys[i].obj.getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ");
      var person = escapeHtml(openpgp.keyring.publicKeys[i].obj.userIds[0].text);
      var length_alg = getAlgorithmString(openpgp.keyring.publicKeys[i].obj);
      var status = (openpgp.keyring.publicKeys[i].obj.verifyBasicSignatures() ? rcmail.gettext('valid', 'rc_openpgpjs') : rcmail.gettext('invalid', 'rc_openpgpjs'));
      var del = "<a href='#' onclick='if(confirm(\"" + rcmail.gettext('delete_pub', 'rc_openpgpjs') + "\")) { openpgp.keyring.removePublicKey(" + i + "); updateKeyManager(); }'>" + rcmail.gettext('delete', 'rc_openpgpjs') + "</a>";
      
      var result = "<tr onclick='displayPub(" + i + ");'>" +
        "<td>" + key_id      + "</td>" +
        "<td>" + fingerprint + "</td>" +
        "<td>" + person      + "</td>" +
        "<td>" + length_alg  + "</td>" +
        "<td>" + status      + "</td>" +
        "<td>" + del         + "</td>" +
        "</tr>";
      $('#openpgpjs_pubkeys tbody').append(result);
    }
    
    // fill key manager private key table
    $('#openpgpjs_privkeys tbody').empty();
    for (var i = 0; i < openpgp.keyring.privateKeys.length; i++) {
      for (var j = 0; j < openpgp.keyring.privateKeys[i].obj.userIds.length; j++) {
        var key_id = "0x" + util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getKeyId()).toUpperCase().substring(8);
        var fingerprint = util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ");
        var person = escapeHtml(openpgp.keyring.privateKeys[i].obj.userIds[j].text);
        var length_alg = getAlgorithmString(openpgp.keyring.privateKeys[i].obj);
        var del = "<a href='#' onclick='if(confirm(\"" + rcmail.gettext('delete_priv', 'rc_openpgpjs') + "\")) { openpgp.keyring.removePrivateKey(" + i + "); updateKeyManager(); }'>" + rcmail.gettext('delete', 'rc_openpgpjs') + "</a>";
        
        var result = "<tr onclick='displayPriv(" + i + ");'>" +
          "<td>" + key_id      + "</td>" +
          "<td>" + fingerprint + "</td>" +
          "<td>" + person      + "</td>" +
          "<td>" + length_alg  + "</td>" +
          "<td>" + del         + "</td>" +
          "</tr>";
        
        $('#openpgpjs_privkeys tbody').append(result);
      }
    }
  }

  /**
   * Displays the armored version of a public key
   * 
   * @param key {Integer} The key id
   */  
  function displayPub(key) {
    $("#importPubkeyField").val(openpgp.keyring.publicKeys[key].armored);
  }

  /**
   * Displays the armored version of a private key
   * 
   * @param key {Integer} The key id
   */  
  function displayPriv(key) {
    var keyid = openpgp.keyring.privateKeys[key].obj.getKeyId();
    $("#importPrivkeyField").val(openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored);
  }

  /**
   * Determine the type of algorithm the key is generated with
   * and return the algorithm as string
   * 
   * @param key {Integer} The key id
   * @result {String} Algorithm type string
   */  
  function getAlgorithmString(key)
  {
    if(typeof(key.publicKeyPacket) != "undefined") {
      var result = key.publicKeyPacket.MPIs[0].mpiByteLength * 8 + "/";
      var sw = key.publicKeyPacket.publicKeyAlgorithm;
    } else {
      // For some reason publicKeyAlgorithm doesn't work directly on the privatekeyPacket, heh
      var result = (key.privateKeyPacket.publicKey.MPIs[0].mpiByteLength * 8 + "/");
      var sw = key.privateKeyPacket.publicKey.publicKeyAlgorithm;
    }

    switch(sw) {
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

  /**
   * Decrypts a encrypted message
   * 
   * @param data {String} The encrypted message data
   */  
  function decrypt(data)
  {
    var msg = openpgp.read_message(data);
    
    if(!msg)
      return false;

    if(!("decrypt" in msg[0]))
      return false;

    // message is only signed, so verify it
    if(!("sessionKeys" in msg[0])) {
      var sender = rcmail.env.sender.match(/<(.*)>$/)[1];
      var pubkey = openpgp.keyring.getPublicKeyForAddress(sender);

      if(msg[0].verifySignature(pubkey))
        rcmail.display_message(rcmail.gettext('signature_match', 'rc_openpgpjs'), "confirmation");
      else
        rcmail.display_message(rcmail.gettext('signature_mismatch', 'rc_openpgpjs'), "error");
      return;
    }

    if(!openpgp.keyring.hasPrivateKey()) {
      rcmail.display_message(rcmail.gettext('no_key_imported', 'rc_openpgpjs'), "error");
      return false;
    }

    if((this.passphrase === 'undefined' || this.passphrase == null) && openpgp.keyring.privateKeys.length > 0) {
      $("#openpgpjs_key_select").dialog('open');
      return false;
    }

    // json string from set_passphrase()
    // obj.id = private key id
    // obj.passphrase = private key passphrase
    passobj = JSON.parse(this.passphrase);

    //TODO: Move to key_select set_passphrase()
    var keyid = openpgp.keyring.privateKeys[passobj.id].obj.getKeyId();
    var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
    var priv_key = openpgp.read_privateKey(privkey_armored);
    var keymat = null;
    var sesskey = null;

    if(!openpgp.keyring.privateKeys[passobj.id].obj.decryptSecretMPIs(passobj.passphrase)) {
      alert(rcmail.gettext('incorrect_pass', 'rc_openpgpjs'));
      $("#openpgpjs_key_select").dialog('open');
      return false;
    }

    // message is encrypted
    for (var i = 0; i< msg[0].sessionKeys.length; i++) {
      if (priv_key[0].privateKeyPacket.publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
        keymat = { key: priv_key[0], keymaterial: priv_key[0].privateKeyPacket};
        sesskey = msg[0].sessionKeys[i];
        break;
      }

      for (var j = 0; j < priv_key[0].subKeys.length; j++) {
        if (priv_key[0].subKeys[j].publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
          keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
          sesskey = msg[0].sessionKeys[i];
          break;
        }
      }
    }

    if (keymat != null) {
      try {
        keymat.keymaterial.decryptSecretMPIs(passobj.passphrase);
      } catch (e) {
        alert(rcmail.gettext('failed_mpi', 'rc_openpgpjs'));
        return false;
      }

      // replace encrypted message with the decrypted message
      $('#messagebody div.message-part pre').html("<strong>********* *BEGIN ENCRYPTED or SIGNED PART* *********</strong><br />" + escapeHtml(msg[0].decrypt(keymat, sesskey)) + "<br /><strong>********** *END ENCRYPTED or SIGNED PART* **********</strong>");
      return true;
    } else {
      alert(rcmail.gettext('key_mismatch', 'rc_openpgpjs'));
    }
  }

  /**
   * Escape some characters into their html entities
   * 
   * @param unsafe {String} The string to escape
   */  
  function escapeHtml(unsafe) {
    return unsafe.replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
  }
  
  function showMessages(msg) { console.log(msg); }
}
