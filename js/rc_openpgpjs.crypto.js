/*
+-------------------------------------------------------------------------+
| OpenPGP.js implemented in Roundcube. This file covers the cryptographic |
| functionalities.                                                        |
|                                                                         |
| Copyright (C) Niklas Femerstrand <nik@qnrq.se>                          |
| Copyright (C) 2014 Lazlo Westerhof <hello@lazlo.me>                     |
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
*/

var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('openpgp'),
  keyring = new openpgp.Keyring();

/**
 * Encrypt (and sign) a message
 *
 * @param publicKeys {Array}  Public keys
 * @param msg    {String} Message to encrypt
 * @param sign    {Bool}   Sign and encrypt the message?
 * @param privateKey {String} Required if sign is True
 * @return {String} Encrypted message
 */
// TODO: Feed key armored and do openpgp.read_* here
function encrypt(publicKeys, msg, sign, privateKey, passphrase) {
  sign = (typeof sign === "undefined") ? 0 : 1;
  if (sign) {
    privateKey = (typeof privateKey === "undefined") ? 0 : privateKey;
    passphrase = (typeof passphrase === "undefined") ? 0 : passphrase;

    if (!privateKey) {
      alert("Missing private key");
      return false;
    }

    if (!passphrase) {
      alert("Missing passphrase");
      return false;
    }

    if (!privateKey.keys[0].decrypt(passphrase)) {
      alert("Password for secrect key was incorrect!");
      return;
    }

    try {
      return openpgp.signAndEncryptMessage(publicKeys, privateKey.keys[0], msg);
    } catch (e) {
      return false;
    }
  }

  try {
    return openpgp.encryptMessage(publicKeys, msg);
  } catch (e) {
    return false;
  }
}

/**
 * Sign a meesage
 *
 * @param msg             {String} Message to sign
 * @param privateKeyArmored {String} Armored private key to sign message
 * @param passphrase      {String} Passphrase of private key
 * @return {String} Signed message
 */
function sign(msg, privateKeyArmored, passphrase) {
  var privateKey = openpgp.key.readArmored(privateKeyArmored).keys;
  if (!privateKey[0].decrypt(passphrase)) {
    alert("WRONG PASS");
  }

  try {
    return openpgp.signClearMessage(privateKey, msg);
  } catch (e) {
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
 * @return {Array} Armored key pair
 */
function generateKeys(bits, algo, ident, passphrase) {
  try {
    var keys = openpgp.generateKeyPair(algo, bits, ident, passphrase);
    return {"public": keys.publicKeyArmored, "private": keys.privateKeyArmored};
  } catch (e) {
    return false;
  }
}

/**
 * Decrypt a message
 *
 * @param msg             {String} Message to decrypt
 * @param privateKeyArmored {String} Armored private key to decrypt message
 * @param passphrase      {String} Passphrase of private key
 * @return {String} Decrypted message
 */
function decrypt(msg, privateKeyArmored, publicKeys, passphrase) {
  var privateKey = openpgp.key.readArmored(privateKeyArmored);

  if (!privateKey.keys[0].decrypt(passphrase)) {
    alert("wrong pass");
    return false;
  }

  try {
    return openpgp.decryptAndVerifyMessage(privateKey.keys[0], publicKeys, msg);
  } catch (e) {
    return false;
  }
}

/**
 * Verify signature of a clear-text message
 *
 * @param msg     {array}  Message to verify
 * @param pubkeys {array}  Public key(s) to verify against
 */
function verify(msg, publicKeys) {
  return msg.verify(publicKeys);
}

/**
 * Parses a message into an OpenPGP Message object and checks if it is
 * a cleartext message.
 *
 * @param msg_armor {String}  Message to parse
 * @return {OpenPGP Message, Boolean}
 */
function parseMsg(msg_armor) {
  // try to read message as cleartext
  try {
    var msg = openpgp.cleartext.readArmored(msg_armor);
    return {
        msg: msg,
        cleartext: true
    };
  } catch(e) {
    // message is not cleartext
    try {
      var msg = openpgp.message.readArmored(msg_armor);
      return {
          msg: msg,
          cleartext: false
      };
    } catch(e) {
       // messsage is invalid
       console.log(e);
    }
  }

}

/**
 * Returns number of public keys in keyring
 *
 * @return {Integer}
 */
function getPubkeyCount() {
  return keyring.publicKeys.keys.length;
}

/**
 * Returns number of private keys in keyring
 *
 * @return {Integer}
 */
function getPrivkeyCount() {
  return keyring.privateKeys.keys.length;
}

/**
 * Returns the fingerprint of a key in the keyring
 *
 * @param i {Integer} Key id in keyring
 * @param private {Boolean} Private key
 * @param niceformat {Boolean} Use nice formatting
 * @return {Integer}
 */
function getFingerprint(i, private=false, niceformat=true) {
  if (private) {
    fingerprint = openpgp.util.hexstrdump(keyring.privateKeys.keys[i].primaryKey.getFingerprint()).toUpperCase();
  } else {
    fingerprint = openpgp.util.hexstrdump(keyring.publicKeys.keys[i].primaryKey.getFingerprint()).toUpperCase();
  }

  if (niceformat) {
    fingerprint = fingerprint.replace(/(.{2})/g, "$1 ");
  } else {
    fingerprint = "0x" + fingerprint.substring(0, 8);
  }

  return fingerprint;
}

/**
 * Returns the id of a key in the keyring
 *
 * @param i {Integer} Key id in keyring
 * @param private {Boolean} Private key
 * @return {Integer}
 */
function getKeyID(i, private=false) {
  if (private) {
    key_id = keyring.privateKeys.keys[i].primaryKey.getKeyId();
  } else {
    key_id = keyring.publicKeys.keys[i].primaryKey.getKeyId();
  }

  return "0x" + key_id.toHex().toUpperCase().substring(8);
}

function getPerson(i, j, private=false) {
  return getKeyUserids(i, private)[j];
}

/**
 * Returns the public key for an address from the keyring
 *
 * @param address {String} Key id in keyring
 * @return {OpenPGP Key}
 */
function getPubkeyForAddress(address) {
  return keyring.publicKeys.getForAddress(address);
}

/**
 * Returns the fingerprint for a sender
 *
 * @param sender {String} Sender
 * @return {OpenPGP Key}
 */
function getFingerprintForSender(sender) {
  var publicKey = getPubkeyForAddress(sender);
  var fingerprint = util.hexstrdump(publicKey[0].obj.getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ");
  return fingerprint;
}

function decryptSecretMPIs(i, p) {
  return keyring.privateKeys.keys[i].decrypt(p);
}

function decryptSecretMPIsForId(id, passphrase) {
  var keyid = keyring.privateKeys.keys[id].primaryKey.getKeyId();
  var privateKeyArmored = keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
  var privateKey = openpgp.key.readArmored(privateKeyArmored);
  return privateKey.keys[0].decryptSecretMPIs(passphrase);
}

/**
 * Imports a public key
 *
 * @param publicKey {String} Armored public keyo
 * @return {Boolean}
 */
function importPubkey(publicKey) {
  try {
    keyring.publicKeys.importKey(publicKey);
    keyring.store();
  } catch (e) {
    return false;
  }
  return true;
}

/**
 * Imports a private key
 *
 * @param privateKey {String} Armored private key
 * @return {Boolean}
 */
function importPrivkey(privateKey, passphrase) {
  try {
    keyring.privateKeys.importKey(privateKey);
    keyring.store();
  } catch (e) {
    return false;
  }

  return true;
}

function parsePrivkey(key) {
  try {
    return openpgp.key.readArmored(key).keys[0];
  } catch (e) {
    return false;
  }
}

/**
 * Tries to temove key from keyring and returns if it is removed.
 *
 * @param i {Integer} Key id in keyring
 * @param private {Boolean} Private key
 * @return {Boolean}
 */
function removeKey(i, private=false) {
  if (private) {
    keyring.privateKeys.removeForId(i);
  } else {
    keyring.publicKeys.removeForId(i);
  }
  keyring.store();
}

/**
 * Returns if key is verified.
 *
 * @param i {Integer} Key id in keyring
 * @return {Boolean}
 */
function verifyBasicSignatures(i) {
  return (keyring.publicKeys.keys[i].verifyPrimaryKey() ? true : false);
}

/**
 * Extracts the algorithm string from a key and return the algorithm type.
 *
 * @param i {Integer} Key id in keyring
 * @return {String} Algorithm type
 */
function getAlgorithmString(i, private=false) {
  if (private) {
    key = keyring.privateKeys.keys[i].primaryKey;
  } else {
    key = keyring.publicKeys.keys[i].primaryKey;
  }

  var result = key.mpi[0].byteLength() * 8 + "/";
  var sw = key.algorithm;

  result += typeToStr(sw);
  return result;
}

/**
 * Get armored key
 *
 * @param i {Integer} Key id in keyring
 * @param private {Boolean} Private key
 * @return {String} Armored key
 */
function getArmored(i, private=false) {
  if (private) {
    return keyring.privateKeys.keys[i].armor();
  } else {
    return keyring.publicKeys.keys[i].armor();
  }
}

function getPrivkeyObj(id) {
  var privateKeyArmored = getArmored(id, true);
  return openpgp.key.readArmored(privateKeyArmored);
}

function getKeyUserids(i, private=false) {
  if (private) {
    return keyring.privateKeys.keys[i].getUserIds();
  } else {
    return keyring.publicKeys.keys[i].getUserIds();
  }
}
