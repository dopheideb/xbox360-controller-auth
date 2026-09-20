#!/usr/bin/env python3

import Cryptodome.Cipher.DES3
import xbox360.auth.base

static_console_data = bytes.fromhex("06 47 2b 2b 09 80 81 82")
static_console_data_sha1_digest = xbox360.auth.base.SHA1(static_console_data)
console_key0 = xbox360.auth.base.des3_encrypt(
	msg=static_console_data_sha1_digest[0:16],
	key=xbox360.auth.base.XSM3_ROOT_KEY_0x23,
)

random_console_data = bytes.fromhex("57 50 02 e6 ea 6f 1a 2d   d4 45 21 89 fd 9c 87 db")
session_key0 = xbox360.auth.base.des3_encrypt(
	msg=random_console_data,
	key=console_key0,
)

random_controller_data = bytes.fromhex("58 f7 b3 7a ef 4a 45 cd   29 32 85 20 e9 26 10 3e")

response = xbox360.auth.base.des3_encrypt(
	msg=random_controller_data + random_console_data,
	key=session_key0,
)
print(response.hex(' '))
assert response == bytes.fromhex("65 7a 87 4e 8a 14 c1 a8 02 17 1c 44 9b ac af a7 af d5 6f cd 1a 7f 28 ba 45 b4 00 61 a5 b9 68 a5")
