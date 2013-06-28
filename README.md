rc_openpgpjs
================

Attention
---------
rc_openpgpjs is currently in an early development stage.

Introduction
------------
rc_openpgpjs is an extension adding OpenPGPs functionality to the Roundcube
webmail project. See [Why do you need PGP?][why], [OpenPGP.js][openpgpjs] and
[Roundcube][roundcube] for more info.

Features
--------
- E-mail PGP signing
- E-mail PGP encryption and decryption
- Secure key storage (HTML5 local storage)
- Key generation
- Key lookups against PGP Secure Key Servers

Key storage
-----------
The keys are stored client side using HTML5 web storage. Private keys are never
transferred from the user's local HTML5 web storage. Private and public keys can
however be exported from the web storage and be used outside of Roundcbe.

Key lookups
-----------
Public keys can be imported from PGP Secure Key Servers like pgp.mit.edu and
any other Public Key Server which follows the [OpenPGP HTTP Keyserver Protocol 
(HKP)][draft].

Installation
------------
1. Copy plugin to 'plugins' folder
2. Add 'rc_openpgpjs' to plugins array in your Roundcube config (config/main.inc.php)

Contact
-------
For any bug reports or feature requests please refer to the [tracking system][issues].

[roundcube]: http://www.roundcube.net/
[openpgpjs]: http://openpgpjs.org/
[issues]: https://github.com/qnrq/rc_openpgpjs/issues
[why]: http://www.pgpi.org/doc/whypgp/en/
[draft]: http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
