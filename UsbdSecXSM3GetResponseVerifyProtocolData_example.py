#!/usr/bin/env python3

import Cryptodome.Cipher.DES3
import Cryptodome.Hash.SHA1
from   typing import Final

def SHA1(msg: bytes) -> bytes:
	sha1 = Cryptodome.Hash.SHA1.new()
	sha1.update(msg)
	return sha1.digest()

def des3_encrypt(msg: bytes, key: bytes) -> bytes:
	cipher = Cryptodome.Cipher.DES3.new(
	        key=key,
	        mode=Cryptodome.Cipher.DES3.MODE_CBC,
	        iv=bytes(8),
	)
	return cipher.encrypt(msg)

XSM3_ROOT_KEY_0x23: Final[bytes] = bytes.fromhex("82 80 78 68 3a 52 3a 98   10 f4 0c 12 70 66 dc ba")

static_console_data = bytes.fromhex("06 47 2b 2b 09 80 81 82")
print(f"static_console_data={static_console_data.hex(':')}")

## The following is reproducable in bash with:
##
##     <<<'06 47 2b 2b 09 80 81 82' xxd -r -plain\
##     | sha1sum
static_console_data_sha1_digest = SHA1(static_console_data)
print(f"static_console_data_sha1_digest[0:16]={static_console_data_sha1_digest[0:16].hex(':')}")
assert static_console_data_sha1_digest[0:16] == bytes.fromhex("7b f6 65 0a 8b dd 9b 9e   8a 8e 54 98 34 36 65 3e")



## The following is reproducable in bash with:
##
##    <<<'06 47 2b 2b 09 80 81 82' xxd -r -plain\
##    | sha1sum\
##    | cut -b 1-32\
##    | xxd -r -plain\
##    | openssl enc -des-ede-cbc -nopad\
##        -iv 0000000000000000\
##        -K '828078683a523a9810f40c127066dcba'
console_key0 = des3_encrypt(
	msg=static_console_data_sha1_digest[0:16],
	key=XSM3_ROOT_KEY_0x23,
)
print(f"console_key0={console_key0.hex(':')}")
assert console_key0 == bytes.fromhex("9a de ee 7b 92 14 d4 5d   67 52 80 f0 d2 56 c0 96")



## The following is reproducable in bash with:
##
##     <<<'57 50 02 e6 ea 6f 1a 2d   d4 45 21 89 fd 9c 87 db' xxd -r -plain\
##     | openssl enc -des-ede-cbc -nopad\
##         -iv 0000000000000000\
##         -K "$(
##             <<<'06 47 2b 2b 09 80 81 82' xxd -r -plain\
##             | sha1sum\
##             | cut -b 1-32\
##             | xxd -r -plain\
##             | openssl enc -des-ede-cbc -nopad\
##                 -iv 0000000000000000\
##                 -K '828078683a523a9810f40c127066dcba'\
##             | xxd -plain
##         )"
random_console_data = bytes.fromhex("57 50 02 e6 ea 6f 1a 2d   d4 45 21 89 fd 9c 87 db")
session_key0 = des3_encrypt(
	msg=random_console_data,
	key=console_key0,
)
print(f"session_key0={session_key0.hex(':')}")
assert session_key0 == bytes.fromhex("0c dd 4f cc 08 f0 55 e4   0e 19 eb b4 ea 46 5c 39")



random_controller_data = bytes.fromhex("58 f7 b3 7a ef 4a 45 cd   29 32 85 20 e9 26 10 3e")
print(f"random_controller_data={random_controller_data.hex(':')}")



## The following is reproducable in bash with:
##
##     <<<'58 f7 b3 7a ef 4a 45 cd   29 32 85 20 e9 26 10 3e    57 50 02 e6 ea 6f 1a 2d   d4 45 21 89 fd 9c 87 db' xxd -r -plain\
##     | openssl enc -des-ede-cbc -nopad\
##         -iv 0000000000000000\
##         -K "$(
##             <<<'57 50 02 e6 ea 6f 1a 2d   d4 45 21 89 fd 9c 87 db' xxd -r -plain\
##             | openssl enc -des-ede-cbc -nopad\
##                 -iv 0000000000000000\
##                 -K "$(
##                     <<<'06 47 2b 2b 09 80 81 82' xxd -r -plain\
##                     | sha1sum\
##                     | cut -b 1-32\
##                     | xxd -r -plain\
##                     | openssl enc -des3 -nopad\
##                         -iv 0000000000000000\
##                         -K '828078683a523a9810f40c127066dcba828078683a523a98'\
##                     | xxd -plain
##                 )"\
##             | xxd -plain
##         )"
response = des3_encrypt(
	msg=random_controller_data + random_console_data,
	key=session_key0,
)
print(response.hex(' '))
assert response == bytes.fromhex("65 7a 87 4e 8a 14 c1 a8 02 17 1c 44 9b ac af a7 af d5 6f cd 1a 7f 28 ba 45 b4 00 61 a5 b9 68 a5")
