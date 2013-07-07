/*
 * +-------------------------------------------------------------------------+
 * | OpenPGP.js implemented in Roundcube. This file covers the cryptographic |
 * | functionalities.                                                        |
 * |                                                                         |
 * | Copyright (C) 2013 Niklas Femerstrand <nik@qnrq.se>                     |
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
 * */

openpgp.init();
// openpgp.config.debug = true

/**
 * Encrypt (and sign) a meesage
 *
 * @param pubkeys {Array}  Public keys
 * @param text    {String} Message to encrypt
 * @param sign    {Bool}   Sign and encrypt the message?
 * @param privkey {String} Required if sign is True
 * @return {String} Encrypted message
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
 * Generates key pair
 *
 * @param bits       {Integer} Key length in bits
 * @param algo       {Integer} Key algorithm type. Currently unused and set to 1 (RSA)
 * @param ident      {String}  Key identity formatted as "Firstname Lastname <foo@bar.com>"
 * @param passphrase {String} Passphrase of private key
 * @return {Array} Key pair
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

/**
 * Sign a meesage
 *
 * @param msg             {String} Message to sign
 * @param privkey_armored {String} Armored private key to sign message
 * @param passphrase      {String} Passphrase of private key
 * @return {String} Signed message
 */
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

/**
 * Decrypt a meesage
 *
 * @param msg             {String} Message to decrypt
 * @param privkey_armored {String} Armored private key to decrypt message
 * @param passphrase      {String} Passphrase of private key
 * @return {String} Decrypted message
 */
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

function parseMsg(msg) {
	return openpgp.read_message(msg);
}

function hasPrivateKey() {
	return openpgp.keyring.hasPrivateKey();
}

function getPrivkeyCount() {
	return openpgp.keyring.privateKeys.length;
}

function getFingerprint(i, private, niceformat) {
	if(typeof(private) !== "undefined") {
		private = false;
	}

	if(typeof(niceformat) == "undefined") {
		alert("undefined");
		niceformat = true;
	}

	if(private == false) {
		fingerprint = util.hexstrdump(openpgp.keyring.publicKeys[i].obj.getFingerprint()).toUpperCase().substring(0, 8);
	} else {
		fingerprint = util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getFingerprint()).toUpperCase().substring(0, 8);
	}

	if(niceformat) {
		fingerprint = fingerprint.replace(/(.{2})/g, "$1 ");
	} else {
		fingerprint = "0x" + fingerprint.substring(0, 8);
	}

	return fingerprint;
}

function getPubkeyForAddress(address) {
	var pubkey = openpgp.keyring.getPublicKeyForAddress(address);
	return pubkey;
}

function getFingerprintForSender(sender) {
	var pubkey = getPubkeyForAddress(sender);
	var fingerprint = util.hexstrdump(pubkey[0].obj.getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ");
	return fingerprint;
}

function getPrivkeyArmored(id) {
	var keyid = openpgp.keyring.privateKeys[id].obj.getKeyId();
	var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
	return privkey_armored;
}
