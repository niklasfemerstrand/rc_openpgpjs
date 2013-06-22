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

if(window.rcmail) {
  rcmail.addEventListener('init', function(evt) {
    openpgp.init();
    this.passphrase = "";
//  openpgp.config.debug = true
    rcmail.addEventListener('plugin.pks_search', pks_search_callback);
    rcmail.enable_command("savedraft", false);

    if(sessionStorage.length > 0) {
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
      $('#openpgpjs_key_search').dialog({ modal: true,
                                          autoOpen: false,
                                          title: rcmail.gettext('key_search', 'rc_openpgpjs'),
                                          width: "60%",
                                          open: function(event, ui) {
                                                   $("#openpgpjs_search_results").html("");
                                                   $("#openpgpjs_search_input").val("");
                                                }
                                        });
      $('#openpgpjs_key_manager').dialog({ modal: true,
                                           autoOpen: false,
                                           title: rcmail.gettext('key_manager', 'rc_openpgpjs'),
                                           width: "90%",
                                           open: function(event, ui) {
                                                    updateKeyManager();
                                                 }
                                         });

      // register open key manager command
      rcmail.register_command('open-key-manager', function() { $("#openpgpjs_key_manager").dialog("open"); });
      rcmail.enable_command('open-key-manager', true);

    if (rcmail.env.action === "compose") {
      rcmail.env.compose_commands.push('open-key-manager');
      rcmail.addEventListener("beforesend", function(e) { if(!beforeSend()) { return false; } });
      $("#composebuttons").prepend("<input id='openpgpjs_encrypt' type='checkbox' checked='checked' /> " + rcmail.gettext('encrypt', 'rc_openpgpjs') + " <input id='openpgpjs_sign' type='checkbox' /> " + rcmail.gettext('sign', 'rc_openpgpjs') + "");
    } else if (rcmail.env.action === 'show' || rcmail.env.action === "preview") {
      decrypt($('#messagebody div.message-part pre').html());
    }
  });

  function generate_keypair(bits, algo)
  {
    if($('#gen_passphrase').val() === '') {
      $('#generate_key_error').removeClass("hidden");
      $('#generate_key_error p').html(rcmail.gettext('enter_pass', 'rc_openpgpjs'));
      return false;
    } else if($("#gen_passphrase").val() !== $("#gen_passphrase_verify").val()) {
      $('#generate_key_error').removeClass("hidden");
      $('#generate_key_error p').html(rcmail.gettext('pass_mismatch', 'rc_openpgpjs'));
      return false;
    }

    // TODO Currently only RSA is supported, fix this when OpenPGP.js implements ElGamal & DSA
    var ident = $("#gen_ident option:selected").text();
    var keys = openpgp.generate_key_pair(1, bits, ident, $('#gen_passphrase').val());
    $('#generated_keys').html("<pre id='generated_private'>" + keys.privateKeyArmored + "</pre><pre id='generated_public'>" + keys.publicKeyArmored  +  "</pre>");
    $('#generate_key_error').addClass("hidden");
    $('#import_button').removeClass("hidden");

    return true;
  }

  function importGenerated()
  {
    $('#import_button').addClass("hidden");
    importPubKey($("#generated_public").html());

    if(importPrivKey($("#generated_private").html(), $("#gen_passphrase").val())) {
      alert(rcmail.gettext('import_gen', 'rc_openpgpjs'));
    }

    $("#gen_passphrase").val("");
    $("#gen_passphrase_verify").val("");
  }

  /*
   * Params:
   *   i: int, used as openpgp.keyring[private|public]Keys[i]
   *   p: str, the passphrase
   */
  function set_passphrase(i, p)
  {
    if(i === "-1")
    {
      $('#key_select_error').removeClass("hidden");
      $('#key_select_error p').html(rcmail.gettext('select_key', 'rc_openpgpjs'));
      return false;
    }

    if(!openpgp.keyring.privateKeys[i].obj.decryptSecretMPIs(p))
    {
      $('#key_select_error').removeClass("hidden");
      $('#key_select_error p').html(rcmail.gettext('incorrect_pass', 'rc_openpgpjs'));
      return false;
    }

    this.passphrase = JSON.stringify({ "id" : i, "passphrase" : p } );

    if($('#messagebody div.message-part pre').length > 0)
    {
      if(!decrypt($('#messagebody div.message-part pre').html())) {
        return false;
      }
    } else {
      if(!encryptAndSend()) {
        return false;
      }
    }

    if($('#openpgpjs_rememberpass').is(':checked')) {
      sessionStorage.setItem(i, this.passphrase);
    }

    $('#key_select_error').addClass("hidden");
    $('#openpgpjs_key_select').dialog('close');
  }

  function sign(encrypt) {
      if(this.passphrase === "" && openpgp.keyring.privateKeys.length > 0)
      {
        $("#openpgpjs_key_select").dialog('open');
        return false;
      } else if(!encrypt && openpgp.keyring.privateKeys.length === 0) {
        alert(rcmail.gettext('no_keys', 'rc_openpgpjs'));
        return false;         
      } else if(openpgp.keyring.privateKeys.length === 0 || openpgp.keyring.publicKeys.length === 0) {
        alert(rcmail.gettext('no_keys', 'rc_openpgpjs'));
        return false;
      }

      passobj = JSON.parse(this.passphrase);
      var keyid = openpgp.keyring.privateKeys[passobj.id].obj.getKeyId();
      var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
      var priv_key = openpgp.read_privateKey(privkey_armored);

      if(!priv_key[0].decryptSecretMPIs(passobj.passphrase)) {
        alert(rcmail.gettext('incorrect_pass', 'rc_openpgpjs'));
      }

      if(!encrypt) {
        signed = openpgp.write_signed_message(priv_key[0], $("textarea#composebody").val());
        if(signed) {
          return signed;
        }
      }

      var pubkeys = new Array();
      var recipients = $("#_to").val().split(",");

      for (var i = 0; i < recipients.length; i++) {
        var recipient = recipients[i].replace(/(.+?<)/, '').replace(/>/, '');
        var pubkey = openpgp.keyring.getPublicKeyForAddress(recipient);
        pubkeys.push(pubkey[0].obj);
        // TODO: For some reason signing can only be made with one recipient pubkey, gotta investigate
        break;
      }

      signed = openpgp.write_signed_and_encrypted_message(priv_key[0], pubkey[0].obj, $("textarea#composebody").val());
      if(signed) {
        return signed;
      }

      return false;
  }

  function fetchRecipientPubkeys() {
    var pubkeys = new Array();

    var c = 0;
    var recipients = [];
    var matches = "";
    var fields = ["_to", "_cc", "_bcc"];
    var re = /[a-zA-Z0-9\._%+-]+@[a-zA-Z0-9\._%+-]+\.[a-zA-Z]{2,4}/g;

    for(field in fields) {
      matches = $("#" + fields[field]).val().match(re);

      for(key in matches) {
        recipients[c] = matches[key];
        c++;
      }
    }

    for (var i = 0; i < recipients.length; i++) {
      var recipient = recipients[i].replace(/(.+?<)/, '').replace(/>/, '');
      var pubkey = openpgp.keyring.getPublicKeyForAddress(recipient);
      if(typeof(pubkey[0]) != "undefined") {
        pubkeys.push(pubkey[0].obj);
      } else {
        // Querying PKS for recipient pubkey
       if(confirm("Couldn't find a public key for " + recipient + ". If you already have it you can import it into the key manager. Would you like to query the key server for the missing key?")) {
          rcmail.http_post("plugin.pks_search", "search=" + recipient + "&op=index");
          $("#openpgpjs_search_input").attr('disabled', 'disabled');
          $("#openpgpjs_search_submit").attr('disabled', 'disabled');
          $("#openpgpjs_key_search").dialog('open');
        }
        return false;
      }
    }

    return pubkeys;
  }

  function beforeSend() {
	if(!$("#openpgpjs_encrypt").is(":checked") &&
       !$("#openpgpjs_sign").is("checked")) {
		return true;
	}

    // Only encrypt, don't sign
    if($("#openpgpjs_encrypt").is(":checked") &&
       !$("#openpgpjs_sign").is(":checked")) {
      // Fetch recipient pubkeys
      var pubkeys = fetchRecipientPubkeys();
      if(pubkeys.length === 0) {
        return false;
      }
      var text = $("textarea#composebody").val();
      var encrypted = encrypt(pubkeys, text);
      $("textarea#composebody").val(encrypted);
      this.finished_treating = 1;
      return true;
    }
    return false;
  }

  function encryptAndSend() {
    if($("#openpgpjs_encrypt").is(":checked") && !$("#openpgpjs_sign").is(":checked")) {
      encrypted = encrypt();
      if(!encrypted) {
        return false;
      }

      $("textarea#composebody").val(encrypted);
      return true;
    }

    if($("#openpgpjs_sign").is(":checked")) {
      if($("#openpgpjs_encrypt").is(":checked")) {
        signed = sign(encrypt = true);
      } else {
        signed = sign(encrypt = false);
      }

      if(signed) {
        $("textarea#composebody").val(signed);
        return true;
      }
    }

    return true;
  }

  function importFromSKS(id) {
    rcmail.http_post('plugin.pks_search', 'search=' + id + '&op=get');
    return;
  }

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
      alert(rcmail.gettext('import_fail', 'rc_openpgpjs'));
      return false;
    }

    return true;
  }

  /**
   * op: (get|index|vindex) string operation to perform
   * search: string phrase to pass to HKP
   *
   * To retrieve all matching keys: pubkey_search("foo@bar", "index")
   * To retrieve armored key of specific id: pubkey_search("0xF00", "get")
   *
   * If op is get then search should be either 32-bit or 64-bit. See
   * http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00#section-3.1.1.1
   * for more details.
   *
   */
  // TODO: Version 3 fingerprint search
  function pubkey_search(search, op) {
    if(search.length === 0) {
      return false;
    }

    rcmail.http_post('plugin.pks_search', 'search=' + search + '&op=' + op);
    return true;
  }

  function pks_search_callback(response) {
    $("#openpgpjs_search_input").removeAttr("disabled");
    $("#openpgpjs_search_submit").removeAttr("disabled");

	if(response.message === "ERR: Missing param") {
		console.log("Missing param");
		return false;
	}

	if(response.message === "ERR: Invalid operation") {
		console.log("Invalid operation");
		return false;
	}

    if(response.message === "ERR: No keys found") {
        alert(rcmail.gettext('no_keys', 'rc_openpgpjs'));
        return false;
    }

    if(response.op === "index") {
      try {
        result = JSON.parse(response.message);
      } catch(e) {
        alert(rcmail.gettext('no_keys', 'rc_openpgpjs'));
        return false;
      }

      $("#openpgpjs_search_results").html("");
      for(var i = 0; i < result.length; i++) {
        $("#openpgpjs_search_results").append("<tr class='" + (i%2 !== 0 ? " odd" : "") + "'><td><a href='#' onclick='importFromSKS(\"" + result[i][0] + "\");'>Import</a></td><td>" + result[i][0] + "</td>" + "<td>" + result[i][1] + "</td></tr>");
      }
    } else if(response.op === "get") {
      k = JSON.parse(response.message);
      $("#importPubkeyField").val(k[0]);
      if(importPubKey($("#importPubkeyField").val())) {
        alert(rcmail.gettext('pubkey_import_success', 'rc_openpgpjs'));
      }
    }
  }

  function importPrivKey(key, passphrase) {
    if(passphrase === '') {
      $('#import_priv_error').removeClass("hidden");
      $('#import_priv_error p').html(rcmail.gettext('enter_pass', 'rc_openpgpjs'));
      return false;
    }

    try {
      privkey_obj = openpgp.read_privateKey(key)[0];
    } catch(e) {
      $('#import_priv_error').removeClass("hidden");
      $('#import_priv_error p').html(rcmail.gettext('import_failed', 'rc_openpgpjs'));
      return false;
    }

    if(!privkey_obj.decryptSecretMPIs(passphrase)) {
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

  // Param i: int, used as openpgp.keyring[private|public]Keys[i]
  function select_key(i) {
    fingerprint = "0x" + util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getKeyId()).toUpperCase().substring(8);
    $("#openpgpjs_selected").html("<strong>" + rcmail.gettext('selected', 'rc_openpgpjs') + ":</strong> " + fingerprint);
    $("#openpgpjs_selected_id").val(i);
    $("#passphrase").val("");
  }

  function updateKeySelector() {
    // Fills key_select key list
    $("#openpgpjs_key_select_list").html("<input type=\"hidden\" id=\"openpgpjs_selected_id\" value=\"-1\" />");

    // Only one key in keyring, nothing to select from
    if(openpgp.keyring.privateKeys.length === 1) {
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

    return true;
  }

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

    // Fills key manager generation ident select
    $("#gen_ident").html("");
    identities = JSON.parse($("#openpgpjs_identities").html());
    for (var i = 0; i < identities.length; i++) {
      $("#gen_ident").append("<option value='" + i + "'>" + escapeHtml(identities[i].name + " <" + identities[i].email + ">") + "</option>");
    }
  }

  function getAlgorithmString(key) {
    if(typeof(key.publicKeyPacket) !== "undefined") {
      var result = key.publicKeyPacket.MPIs[0].mpiByteLength * 8 + "/";
      var sw = key.publicKeyPacket.publicKeyAlgorithm;
    } else {
      // For some reason publicKeyAlgorithm doesn't work directly on the privatekeyPacket, heh
      var result = (key.privateKeyPacket.publicKey.MPIs[0].mpiByteLength * 8 + "/");
      var sw = key.privateKeyPacket.publicKey.publicKeyAlgorithm;
    }

    result += typeToStr(sw);

    return result;
  }

  // Converts an integer (1/2/3/16/17) to corresponding algorithm type (str)
  function typeToStr(id) {
    var r = ""

    switch(id) {
      case 1:
        r = "RSA(S/E)";
        break;
      case 2:
        r = "RSA(E)";
        break;
      case 3:
        r = "RSA(S)";
        break;
      case 16:
        r = "Elg";
        break;
      case 17:
        r = "DSA";
        break;
      default:
        r = "UNKNOWN";
        break;
    }

    return(r);
  }
  
  function decrypt(data) {
    var msg = openpgp.read_message(data);
    
    if(!msg) {
      return false;
    }

    if(!("decrypt" in msg[0])) {
      return false;
    }

    var sender = rcmail.env.sender.match(/<(.*)>$/)[1];
    var pubkey = openpgp.keyring.getPublicKeyForAddress(sender);
    var fingerprint = util.hexstrdump(pubkey[0].obj.getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ");

    if(typeof(this.getinfo) == "undefined") {
      $(".headers-table").css( "float", "left" );
      $(".headers-table").after("<div id='openpgpjs_info'><table><tbody></tbody></table></div>");

      // Carefully escape anything that is appended to the info table, otherwise
      // anyone clever enough to write arbitrary data to their pubkey has a clear
      // exploitation path.
      $("#openpgpjs_info table tbody").append("<tr><td>Key algo:</td><td>" + typeToStr(msg[0].type) + "</td></tr>");
      $("#openpgpjs_info table tbody").append("<tr><td>Created:</td><td>" + escapeHtml(String(msg[0].messagePacket.creationTime))  + "</td></tr>");
      $("#openpgpjs_info table tbody").append("<tr><td>Fingerprint:</td><td>" + fingerprint + "</td></tr>");
      this.getinfo = false;
    }

    // msg is only signed, so verify it
    if(!("sessionKeys" in msg[0])) {
      if(msg[0].verifySignature(pubkey)) {
        rcmail.display_message(rcmail.gettext('signature_match', 'rc_openpgpjs'), "confirmation");
      } else {
        rcmail.display_message(rcmail.gettext('signature_mismatch', 'rc_openpgpjs'), "error");
      }

      return;
    }

    if(!openpgp.keyring.hasPrivateKey()) {
      rcmail.display_message(rcmail.gettext('no_key_imported', 'rc_openpgpjs'), "error");
      return false;
    }

    if(this.passphrase === "" && openpgp.keyring.privateKeys.length > 0) {
      $("#openpgpjs_key_select").dialog('open');
      return false;
    }

    // json string from set_passphrase, obj.id = privkey id, obj.passphrase = privkey passphrase
    passobj = JSON.parse(this.passphrase);

    // TODO Move to key_select set_passphrase()
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

    // msg is encrypted
    for (var i = 0; i< msg[0].sessionKeys.length; i++) {
      if (priv_key[0].privateKeyPacket.publicKey.getKeyId() === msg[0].sessionKeys[i].keyId.bytes) {
        keymat = { key: priv_key[0], keymaterial: priv_key[0].privateKeyPacket};
        sesskey = msg[0].sessionKeys[i];
        break;
      }

      for (var j = 0; j < priv_key[0].subKeys.length; j++) {
        if (priv_key[0].subKeys[j].publicKey.getKeyId() === msg[0].sessionKeys[i].keyId.bytes) {
          keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
          sesskey = msg[0].sessionKeys[i];

          break;
        }
      }
    }

    if (keymat !== null) {
      try {
        keymat.keymaterial.decryptSecretMPIs(passobj.passphrase);
      } catch (e) {
        alert(rcmail.gettext('failed_mpi', 'rc_openpgpjs'));
        return false;
      }

      $('#messagebody div.message-part pre').html("<strong>********* *BEGIN ENCRYPTED or SIGNED PART* *********</strong><br />" + escapeHtml(msg[0].decrypt(keymat, sesskey)) + "<br /><strong>********** *END ENCRYPTED or SIGNED PART* **********</strong>");
      return true;
    } else {
      alert(rcmail.gettext('key_mismatch', 'rc_openpgpjs'));
    }
  }

  function escapeHtml(unsafe) {
        return unsafe.replace(/&/g, "&amp;")
                     .replace(/</g, "&lt;")
                     .replace(/>/g, "&gt;")
                     .replace(/"/g, "&quot;")
                     .replace(/'/g, "&#039;");
  }
  
  function showMessages(msg) { console.log(msg); }
}
