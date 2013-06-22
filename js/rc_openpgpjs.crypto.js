/*
 * +-------------------------------------------------------------------------+
 * | OpenPGP.js implemented in Roundcube. This file covers the cryptographic |
 * | functionalities.                                                        |
 * |                                                                         |
 * | This program is free software; you can redistribute it and/or modify    |
 * | it under the terms of the GNU General Public License version 2          |
 * | as published by the Free Software Foundation.                           |
 * |                                                                         |
 * | This program is distributed in the hope that it will be useful,         |
 * | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 * | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 * | GNU General Public License for more details.                            |
 * |                                                                         |
 * | You should have received a copy of the GNU General Public License along |
 * | with this program; if not, write to the Free Software Foundation, Inc., |
 * | 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.             |
 * |                                                                         |
 * +-------------------------------------------------------------------------+
 * | Author: Niklas Femerstrand <nik@qnrq.se>                                |
 * +-------------------------------------------------------------------------+
 * */

/**
 * Params:
 *   pubkeys : Array containing public keys
 *   text    : String to encrypt
 *   sign    : Optional bool, if sign and encrypt set to 1
 *   privkey : Required if sign is set
 * Return:
 *   Encrypted message (str)
 */
// TODO: Feed key armored and do openpgp.read_* here
function encrypt(pubkeys, text, sign, privkey, passphrase) {
  sign = (typeof sign === "undefined") ? 0 : 1;
  if(sign) {
    privkey = (typeof privkey === "undefined") ? 0 : privkey;
    passphrase = (typeof passphrase === "undefined") ? 0 : passphrase;

    if(!privkey) {
      alert("missing privkey");
      return false;
    }

    if(!passphrase) {
      alert("missing passphrase");
      return false;
    }

    if (!privkey[0].decryptSecretMPIs(passphrase)) {
        alert("Password for secrect key was incorrect!");
        return;
	}

    try {
      encrypted = openpgp.write_signed_and_encrypted_message(privkey[0], pubkeys, text);
      return(encrypted);
    } catch (e) {
      return false;
    }
  }

  try {
    encrypted = openpgp.write_encrypted_message(pubkeys, text);
    return(encrypted);
  } catch(e) {
    return false;
  }
}

/**
 * Returns array:
 *   ["private"] = privkey (armored)
 *   ["public"] = pubkey (armored)
 */
function generateKeys(bits, algo, ident, passphrase) {
  try {
    keys = openpgp.generate_key_pair(1, bits, ident, passphrase);
    arr = new Array();
    arr["private"] = keys.privateKeyArmored;
    arr["public"] = keys.publicKeyArmored;
    return(arr);
  } catch(e) {
    return false;
  }
}

function sign(msg, privkey_armored, passphrase) {
  var priv_key = openpgp.read_privateKey(privkey_armored);

  if(!priv_key[0].decryptSecretMPIs(passphrase)) {
	alert("WRONG PASS");
  }

  try {
    var signed = openpgp.write_signed_message(priv_key[0], msg);
	return(signed);
  } catch(e) {
    return false;
  }
}

function decrypt(msg, privkey_armored, passphrase) {
  if(!("decrypt" in msg[0])) {
    return false;
  }

  var priv_key = openpgp.read_privateKey(privkey_armored);
  var keymat = null;
  var sesskey = null;

  if(!priv_key[0].decryptSecretMPIs(passphrase)) {
    alert("wrong pass");
    return false;
  }

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

  try {
    decrypted = msg[0].decrypt(keymat, sesskey);
    return decrypted;
  } catch (e) {
    return false;
  }
}
