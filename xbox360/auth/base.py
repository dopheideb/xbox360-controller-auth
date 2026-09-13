import Cryptodome.Cipher.DES
import Cryptodome.Cipher.DES3
import Cryptodome.Hash
import logging
logger = logging.getLogger(__name__)
import random
import struct
from   typing import Final, Self, cast
import xbox360.auth.xecrypt



## Both keys (0x1D and 0x1E) are present in every Xbox 360's keyvault.
##
## Xbox 360 keyvault offset: seen 0x128, seen 0x138
XSM3_KEY_0x1D: Final[bytes] = bytes.fromhex("e3 5b fb 1c cd ad 32 5b   f7 0e 07 fd 62 3d a7 c4")
## Xbox 360 keyvault offset: seen 0x138, seen 0x148
XSM3_KEY_0x1E: Final[bytes] = bytes.fromhex("8f 29 08 38 0b 5b fe 68   7c 26 46 2a 51 f2 bc 19")

## Global device keys from devkit keyvaults, from 
## https://github.com/InvoxiPlayGames/libxsm3/blob/master/xsm3.c
#XSM3_KEY_0x1D: Final[bytes] = bytes.fromhex("C2 15 E5 5E E5 51 94 2A   EC 3D 45 EC B6 E6 F2 16")
#XSM3_KEY_0x1E: Final[bytes] = bytes.fromhex("C7 45 AD 1F 08 0B D9 E9   9B 1C 34 E3 A4 6D C8 C4")



## Retail keys for generating 0x23/0x24 keys from console ID, from 
## https://github.com/InvoxiPlayGames/libxsm3/blob/master/xsm3.c
XSM3_ROOT_KEY_0x23: Final[bytes] = bytes.fromhex("82 80 78 68 3a 52 3a 98   10 f4 0c 12 70 66 dc ba")
XSM3_ROOT_KEY_0x24: Final[bytes] = bytes.fromhex("66 62 1a 78 f8 60 9c 8a   26 9a 04 ae d8 5c 1e c8")

## devkit recovery keys for generating 0x23/0x24 keys from console ID, 
## from https://github.com/InvoxiPlayGames/libxsm3/blob/master/xsm3.c
#XSM3_ROOT_KEY_0x23: Final[bytes] = bytes.fromhex("b9 e0 9e 68 04 83 91 b3   32 45 7a da 43 6b 80 ad")
#XSM3_ROOT_KEY_0x24: Final[bytes] = bytes.fromhex("92 5d 29 6e b0 61 0b f1   d6 29 3b c8 c7 d9 32 bc")



## The 3DES key is actually a two-key 3DES key: s[0] == s[2]; first and 
## last key are equal.
DES3_KEY_0x1D: Final[bytes] = XSM3_KEY_0x1D + XSM3_KEY_0x1D[0:8]
DES3_KEY_0x1E: Final[bytes] = XSM3_KEY_0x1E + XSM3_KEY_0x1E[0:8]



class AuthBase:
	def __init__(self: Self) -> None:
		logger.debug(f"DES3_KEY_0x1D={DES3_KEY_0x1D.hex(':')}")
		logger.debug(f"DES3_KEY_0x1E={DES3_KEY_0x1E.hex(':')}")
		self.reset()

	def reset(self: Self) -> None:
		self._static_console_data: bytes|None = None
		self._random_console_data: bytes|None = None

		self._static_controller_data: bytes|None = None
		self._random_controller_data: bytes|None = None

		self._challenge_data: bytes|None = None
		self._challenge_response_sha1: bytes|None = None

		self._xsm3_kv_2des_key: tuple[bytes, bytes]|None = None
		self._verify_iv: bytes|None = None
		self._derived_category_key: tuple[bytes,bytes]|None = None



	@property
	def challenge_data(self: Self) -> bytes:
		""" Get the challenge data.

		During UsbdSecXSM3SetVerifyProtocolData2, the host sends 
		8 bytes of random data, to challenge the device.
		"""
		if self._challenge_data is None:
			raise RuntimeError("challenge_data has not been initialized.")
		return self._challenge_data

	@challenge_data.setter
	def challenge_data(self: Self, data: bytes) -> bytes:
		""" Set the challenge data.

		During UsbdSecXSM3SetVerifyProtocolData2, the host sends 
		8 bytes of random data, to challenge the device.
		"""
		required_len = 8
		if len(data) != required_len:
			raise ValueError(f"The challenge data must be 8 bytes long, not {len(data)}.")
		self._challenge_data = data



	@property
	def challenge_response_sha1(self: Self) -> bytes:
		if self._challenge_response_sha1 is None:
			raise RuntimeError("challenge_response_sha1 has not been initialized.")
		return self._challenge_response_sha1

	@challenge_response_sha1.setter
	def challenge_response_sha1(self: Self, sha1: bytes) -> bytes:
		required_len = 20
		if len(sha1) != required_len:
			raise ValueError(f'A SHA1 is exactly {required_len} bytes, not {len(sha1)}.')

		logger.debug(f"Setting challenge_response_sha1 to {sha1.hex(':')}.")
		self._challenge_response_sha1 = sha1



	@property
	def derived_category_key(self: Self) -> tuple[bytes, bytes]:
		if self._derived_category_key is None:
			raise RuntimeError("derived_category_key has not been initialized.")
		return self._derived_category_key

	@derived_category_key.setter
	def derived_category_key(self: Self, keypair: tuple[bytes, bytes]) -> None:
		self._derived_category_key = keypair
		logger.debug(f"self._derived_category_key[0]={self._derived_category_key[0].hex(':')}")
		logger.debug(f"self._derived_category_key[1]={self._derived_category_key[1].hex(':')}")



	@property
	def static_console_data(self: Self) -> bytes:
		if self._static_console_data is None:
			raise RuntimeError("static_console_data has not been initialized.")
		return self._static_console_data

	@static_console_data.setter
	def static_console_data(self: Self, data: bytes) -> None:
		required_len = 8
		if len(data) != required_len:
			raise ValueError(f'We need exactly {required_len} bytes, not {len(data)}.')

		logger.debug(f"Setting static_console_data to {data.hex(':')}.")
		self._static_console_data = data

		## The device and the host use encryption based on the 
		## static console data. Since that data is now known, 
		## the device can calculate the keys.
		self.initialize_console_encryption_keys(
			self.static_console_data
		)



	@property
	def random_console_data(self: Self) -> bytes:
		if self._random_console_data is None:
			raise RuntimeError("random_console_data has not been initialized.")
		return self._random_console_data

	@random_console_data.setter
	def random_console_data(self: Self, data: bytes) -> None:
		logger.debug(f"data={data.hex(':')}")
		required_len = 16
		if len(data) != required_len:
			raise ValueError(f'We need exactly {required_len} bytes, not {len(data)}.')

		logger.debug(f"Setting random_console_data to {data.hex(':')}.")
		self._random_console_data = data

		derived_category_key0 = des3_encrypt(
			msg=self.random_console_data,
			key=self.console_encryption_keys[0],
		)
		derived_category_key1 = des3_encrypt(
			msg=self.random_console_data[8:] + self.random_console_data[0:8],
			key=self.console_encryption_keys[1],
		)
		self.derived_category_key = (derived_category_key0, derived_category_key1)





	@property
	def static_controller_data(self: Self) -> bytes:
		if self._static_controller_data is None:
			raise RuntimeError("static_controller_data has not been initialized.")
		return self._static_controller_data

	@static_controller_data.setter
	def static_controller_data(self: Self, data: bytes) -> None:
		required_len = 24
		if len(data) != required_len:
			raise ValueError(f'We need exactly {required_len} bytes, not {len(data)}.')

		logger.debug(f"Setting static_controller_data to {data.hex(':')}.")
		self._static_controller_data = data

	@property
	def random_controller_data(self: Self) -> bytes:
		if self._random_controller_data is None:
			raise RuntimeError("random_controller_data has not been initialized.")
		return self._random_controller_data

	@random_controller_data.setter
	def random_controller_data(self: Self, data: bytes) -> None:
		required_len = 16
		if len(data) != required_len:
			raise ValueError(f'We need exactly {required_len} bytes, not {len(data)}.')

		logger.debug(f"Setting random_controller_data to {data.hex(':')}.")
		self._random_controller_data = data



	@property
	def verify_iv(self: Self) -> bytes:
		if self._verify_iv is None:
			raise RuntimeError("verify_iv has not been initialized.")
		return self._verify_iv

	@verify_iv.setter
	def verify_iv(self: Self, iv: bytes) -> None:
		assert len(iv) == 8
		self._verify_iv = iv
		logger.debug(f"self._verify_iv={self._verify_iv.hex(':')}")

	def increase_verify_iv(self: Self) -> bytes:
		## Note: '>Q' is the format for 8 bytes big endian.
		quad_BE = '>Q'
		self.verify_iv = struct.pack(
			quad_BE,
			1 + struct.unpack(quad_BE, self.verify_iv)[0],
		)
		return self.verify_iv



	@property
	def console_encryption_keys(self: Self) -> tuple[bytes, bytes]:
		if self._xsm3_kv_2des_key is None:
			raise RuntimeError("console_encryption_keys has not been initialized.")
		return self._xsm3_kv_2des_key

	def initialize_console_encryption_keys(
			self: Self,
			static_console_data: bytes,
	) -> None:
		""" Initialize the console specific encryption keys.

		Part of the communication between console and device is 
		encrypted with 2 two-key 3DES keys based on the 
		console's static data. This method computes those 2 3DES 
		keys.
		"""
		self._xsm3_kv_2des_key = derive_console_encryption_keys(
			static_console_data,
		)
		logger.debug(f"self._xsm3_kv_2des_key[0]={self._xsm3_kv_2des_key[0].hex(':')}")
		logger.debug(f"self._xsm3_kv_2des_key[1]={self._xsm3_kv_2des_key[1].hex(':')}")
		return None

	def ACR(self: Self, input: bytes, key: bytes) -> bytes:
		logger.debug("ACR called.")

		logger.debug(f"self.static_console_data={self.static_console_data.hex(':')}")
		logger.debug(f"input={input.hex(':')}")
		logger.debug(f"key={key.hex(':')}")

		block = input[0:4] + self.static_console_data[0:4]
		logger.debug(f"block={block.hex(':')}")

		iv = xbox360.auth.xecrypt.XeCrypt.ParveEcb(
			key=key,
			inp=input[0x10:0x10 + 8],
		)
		logger.debug(f"iv={iv.hex(':')}")

		cd = xbox360.auth.xecrypt.XeCrypt.ParveEcb(
			key=key,
			inp=block,
		)
		logger.debug(f"cd={cd.hex(':')}")

		UsbdSecPlainTextData = bytes([
			0xD1, 0xD2, 0xF2, 0x80, 0x6E, 0xBA, 0x0C, 0xC0,
			0xB6, 0xC4, 0xC9, 0xD8, 0x61, 0x75, 0x1D, 0x1A,
			0x3F, 0x95, 0x58, 0xBE, 0xD8, 0x0D, 0xE2, 0xC0,
			0xD0, 0x21, 0x79, 0x20, 0x65, 0x2D, 0x99, 0x40,
			0x3C, 0x96, 0x52, 0x00, 0x1B, 0x7F, 0xDC, 0x01,
			0x82, 0x1C, 0x13, 0xD8, 0x33, 0x69, 0x80, 0x40,
			0xFC, 0x97, 0xEA, 0xDE, 0x08, 0xEA, 0x14, 0xDC,
			0xEB, 0x0F, 0x6A, 0x18, 0x6F, 0x78, 0x2C, 0xB0,
			0xD3, 0xC2, 0x40, 0xC7, 0x82, 0x6B, 0x56, 0xA0,
			0x19, 0x09, 0x36, 0xE0, 0x72, 0x70, 0xB1, 0x8C,
			0xE3, 0x0D, 0xAE, 0x7E, 0x50, 0xA5, 0x2B, 0xE2,
			0xC9, 0xAF, 0xC7, 0x70, 0x1C, 0x29, 0x80, 0x56,
			0x24, 0xF0, 0x66, 0xFA, 0x02, 0x2B, 0x58, 0x98,
			0x8F, 0xE4, 0xD1, 0x3C, 0x6E, 0x38, 0x2A, 0xFF,
			0xB8, 0xFA, 0x35, 0xB0, 0x52, 0x49, 0xC5, 0xB4,
			0x66, 0xFA, 0x47, 0x55, 0x6C, 0x8D, 0x40, 0x08,
		])

		ab = xbox360.auth.xecrypt.XeCrypt.ParveCbcMac(
			msg=UsbdSecPlainTextData,
			key=key,
			iv=iv,
		)
		logger.debug(f"ab={ab.hex(':')}")

		result = xbox360.auth.xecrypt.XeCrypt.ChainAndSumMac(cd, ab, UsbdSecPlainTextData)
		return Cryptodome.Util.strxor.strxor(
			term1=result,
			term2=ab,
			output=None
		)



def checksum(data: bytes) -> int:
	logger.debug(f"Calculating checksum over {data.hex(':')}.")
	cksum = 0
	for byte in data:
		cksum ^= byte
	logger.debug(f"Checksum over {data.hex(':')} is {cksum:#04x}.")
	return cksum



def derive_console_encryption_keys(
		static_console_data: bytes,
) -> tuple[bytes, bytes]:
	## SHA1 is used to transform the static console data into 20 
	## bytes of (sortof) random bytes.
	static_console_data_sha1_digest = SHA1(
		static_console_data
	)
	logger.debug(f"static_console_data_sha1_digest={static_console_data_sha1_digest.hex(':')}")
	## Security note: the static console data is send during 
	## UsbdSecXSM3SetChallengeProtocolData. The data is always 
	## encrypted with the 0x1D key, and, since that key is publicly 
	## available, the static console data can always be 
	## sniffed/determines from the 
	## UsbdSecXSM3SetChallengeProtocolData packet.
	## 
	## But this also implies that the SHA1 of the static console 
	## data can always be determined. This weakens the overal 
	## security of the key derivation process a lot, since it 
	## basically 1 of the 2 steps.

	## Note: a SHA1 digest is 160 bit, i.e. 20 bytes. First 16 bytes 
	## are used for the first key, last 16 bytes are used for the 
	## second key. Hence, the messages that will be encrypted, have 
	## 12 bytes in common.
	console_key0 = des3_encrypt(
		msg=static_console_data_sha1_digest[0:16],
		key=XSM3_ROOT_KEY_0x23,
	)
	logger.debug(f"console_key0={console_key0.hex(':')}")

	console_key1 = des3_encrypt(
		msg=static_console_data_sha1_digest[4:20],
		key=XSM3_ROOT_KEY_0x24,
	)
	logger.debug(f"console_key1={console_key1.hex(':')}")

	return (console_key0, console_key1)



def des_decrypt(msg: bytes, key: bytes, iv: bytes) -> bytes:
	""" Decrypt a message with DES (not 3DES).
	"""
	cipher = Cryptodome.Cipher.DES.new(
		key=key,
		mode=Cryptodome.Cipher.DES.MODE_CBC,
		iv=iv,
	)
	return cipher.decrypt(msg)



def des_encrypt(msg: bytes, key: bytes, iv: bytes) -> bytes:
	""" Encrypt a message with DES (not 3DES).
	"""
	cipher = Cryptodome.Cipher.DES.new(
		key=key,
		mode=Cryptodome.Cipher.DES.MODE_CBC,
		iv=iv,
	)
	return cipher.encrypt(msg)



def des3_decrypt(msg: bytes, key: bytes) -> bytes:
	""" Decrypt a message with 3DES.
	"""
	cipher = Cryptodome.Cipher.DES3.new(
		key=key,
		mode=Cryptodome.Cipher.DES3.MODE_CBC,
		iv=bytes(8),
	)
	return cipher.decrypt(msg)

def des3_encrypt(msg: bytes, key: bytes) -> bytes:
	""" Encrypt a message with 3DES.
	"""
	cipher = Cryptodome.Cipher.DES3.new(
		key=key,
		mode=Cryptodome.Cipher.DES3.MODE_CBC,
		iv=bytes(8),
	)
	return cipher.encrypt(msg)



def MAC(data: bytes, key: bytes, iv: bytes) -> bytes:
	logger.debug(f"data={data.hex(':')}")
	logger.debug(f"key={key.hex(':')}")
	logger.debug(f"iv={iv.hex(':')}")
	assert len(key) in [16, 24]

	## Encrypt with DES (not 3DES), use only the last block.
	des_cipher = Cryptodome.Cipher.DES.new(
		key=key[0:8],				## A single DES key is only 8 bytes.
		mode=Cryptodome.Cipher.DES.MODE_CBC,
		iv=iv,
	)
	if iv != bytes(8):
		des_cipher.encrypt(bytes(8))
	last_encrypted_block = des_cipher.encrypt(data)[-8:]
	logger.debug(f"last_encrypted_block={last_encrypted_block.hex(':')}")

	## Weird: flip first bit.
	last_encrypted_block_with_msb_flipped = (
		bytes([last_encrypted_block[0] ^ 0x80])
		+
		last_encrypted_block[1:8]
	)
	logger.debug(f"last_encrypted_block_with_msb_flipped={last_encrypted_block_with_msb_flipped.hex(':')}")

	mac = des3_encrypt(
		msg=last_encrypted_block_with_msb_flipped,
		key=key,
	)
	logger.debug(f"mac={mac.hex(':')}")
	return mac



def SHA1(msg: bytes) -> bytes:
	sha1 = Cryptodome.Hash.SHA1.new()
	sha1.update(msg)
	return sha1.digest()
