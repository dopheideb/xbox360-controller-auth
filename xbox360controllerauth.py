from   Cryptodome.Cipher import DES, DES3
from   Cryptodome.Hash import SHA1
import logging
logger = logging.getLogger(__name__)
import struct
from   typing import Final, Self


## Both keys are in both the Xbox 360 and the controller.
##
## Xbox 360 keyvault offset: seen 0x128, seen 0x138
XSM3_KEY_0x1D: Final[bytes] = bytes.fromhex("e3 5b fb 1c cd ad 32 5b   f7 0e 07 fd 62 3d a7 c4")
## Xbox 360 keyvault offset: seen 0x138, seen 0x148
XSM3_KEY_0x1E: Final[bytes] = bytes.fromhex("8f 29 08 38 0b 5b fe 68   7c 26 46 2a 51 f2 bc 19")



XSM3_ROOT_KEY_0x23: Final[bytes] = bytes.fromhex("82 80 78 68 3a 52 3a 98   10 f4 0c 12 70 66 dc ba")
XSM3_ROOT_KEY_0x24: Final[bytes] = bytes.fromhex("66 62 1a 78 f8 60 9c 8a   26 9a 04 ae d8 5c 1e c8")



## The 3DES key is actually a 2DES key: s[0] == s[2]; first and last key 
## are equal.
DES3_KEY_0x1D: Final[bytes] = XSM3_KEY_0x1D + XSM3_KEY_0x1D[0:8]
DES3_KEY_0x1E: Final[bytes] = XSM3_KEY_0x1E + XSM3_KEY_0x1E[0:8]



class Xbox360ControllerAuth:
	def __init__(self) -> None:
		logger.debug(f"DES3_KEY_0x1D={DES3_KEY_0x1D.hex(':')}")
		logger.debug(f"DES3_KEY_0x1E={DES3_KEY_0x1E.hex(':')}")
		self._console_id = None
		self._random_device_data = None
		self._static_device_data = None
		self._xsm3_kv_2des_key_1 = None
		self._xsm3_kv_2des_key_2 = None
		pass



	@property
	def random_device_data(self) -> None:
		return self._random_device_data

	@random_device_data.setter
	def random_device_data(self, data: bytes) -> None:
		if len(data) != 16:
			raise ValueError('We need exactly 16 bytes.')
		self._random_device_data = data



	@property
	def static_device_data(self) -> None:
		return self._static_device_data

	@static_device_data.setter
	def static_device_data(self, data: bytes) -> None:
		if len(data) != 32:
			raise ValueError(f"We need exactly 32 bytes, not {len(data)}.")
		self._static_device_data = data
		logger.debug(f"static_device_data={self.static_device_data.hex(':')}")



	def parse_IN_packet(self, packet: bytes) -> None:
		if len(packet) == 0x02:
			if packet == b"\x01\x00":
				logger.debug("Peripheral device is not ready.")
				return

			if packet == b"\x02\x00":
				logger.debug("Peripheral device is ready.")
				return

			raise ValueError(f"Unknown 2 byte packet {packet}.")

		if len(packet) == 0x1D:
			## This is the response to:
			## 
			##   bmRequestType	0xc1
			##   bRequest		0x81 (129)
			##   wValue		0x5b17 (0x17 == 0x1d - 5 - 1)
			##   wIndex		0x0103 (259)
			##   wLength		0x001d (29)
			static_data = bytearray(0x20)
			payload = packet[5:]
			static_data[0x00:0x00 + 0xf] = payload[0x00:0x00 + 0xf]
			static_data[0x0f           ] = 0
			static_data[0x10:0x10 + 0x2] = payload[0x0f:0x0f + 0x2]
			static_data[0x12:0x12 + 0x2] = payload[0x11:0x11 + 0x2]
			static_data[0x14           ] = payload[0x13           ]
			static_data[0x15           ] = payload[0x16           ]
			static_data[0x16:0x16 + 0x2] = payload[0x14:0x14 + 0x2]
			self.static_device_data = static_data
			return

		if len(packet) == 0x2E:
			## This is the response to:
			## 
			##   bmRequestType	0xc1
			##   bRequest		0x83 (131)
			##   wValue		0x5b28 (0x28 == 0x2e - 5 - 1)
			##   wIndex		0x0103 (259)
			##   wLength		0x002e (46)
			logger.debug("STUB")
			return


		raise ValueError(f"Unknown IN packet {packet}.")

	def parse_OUT_packet(self, packet: bytes) -> bytes:
		if (
			packet[0] == 0x41
			and
			packet[1] == 0x82
			and
			packet[2:4] == b"\x03\x00"
			and
			packet[4:6] == b"\x03\x01"
			and
			packet[6:8] == b"\x22\x00"
		):
			payload = packet[8:]
			logger.debug(f"Challenge number 1 from Xbox 360 to device: {payload.hex(':')}")
			return self.parse_challenge_data1(payload)

		if (
			packet[0] == 0x41
			and
			packet[1] == 0x84
			and
			packet[2:4] == b"\x03\x00"
			and
			packet[4:6] == b"\x03\x01"
			and
			packet[6:8] == b"\x00\x00"
		):
			payload = packet[8:]
			assert len(payload) == 0
			logger.debug(f"Xbox 360 says we passed the previous challenge.")
			return b""

		if (
			packet[0] == 0x41
			and
			packet[1] == 0x87
			and
			packet[2:4] == b"\x03\x00"
			and
			packet[4:6] == b"\x03\x01"
			and
			packet[6:8] == b"\x16\x00"
		):
			payload = packet[8:]
			logger.debug(f"Challenge number 2 from Xbox 360 to device: {payload.hex(':')}")
			return self.parse_challenge_data2(payload)

		raise ValueError(f"Unknown OUT packet {packet}.")



	def parse_challenge_data1(self: Self, data: bytes) -> None:
		header = data[0:5]
		payload = data[5:]

		## Split the payload.
		encrypted_data = payload[0:-5]
		logger.debug(f"encrypted_data={encrypted_data.hex(':')}")

		provided_mac = payload[-5:-1]
		logger.debug(f"provided_mac={provided_mac.hex(':')}")

		provided_checksum = payload[-1]
		logger.debug(f"provided_checksum={provided_checksum:02x}")



		## Verify the checksum.
		computed_checksum = Xbox360ControllerAuth.checksum(data)
		logger.debug(f"computed_checksum={computed_checksum:02x}")
		assert provided_checksum == computed_checksum

		## Only the last 4 bytes of the MAC are actually used. 
		## (The provided MAC is also only 4 bytes.)
		computed_mac = Xbox360ControllerAuth.MAC(
			data=encrypted_data,
			key=DES3_KEY_0x1E,
			iv=bytes(8),
		)[4:8]
		## Verify MAC.
		if provided_mac != computed_mac:
			logger.error(f"Provided MAC ({provided_mac.hex(':')}) and computed MAC ({computed_mac.hex(':')}) differ!")
		else:
			logger.debug(f"Provided MAC ({provided_mac.hex(':')}) and computed MAC ({computed_mac.hex(':')}) match.")
		assert provided_mac == computed_mac

		## Decrypt the encrypted data.
		cipher = DES3.new(
			key=DES3_KEY_0x1D,
			mode=DES3.MODE_CBC,
			iv=bytes(8),		## !Zero IV!
		)
		decrypted_host_data = cipher.decrypt(payload[0:0x18])
		logger.debug(f"decrypted_host_data={decrypted_host_data.hex(':')}")

		self._random_host_data = decrypted_host_data[0:0x10]
		logger.debug(f"self._random_host_data={self._random_host_data.hex(':')}")

		random_host_data__swapped = self._random_host_data[8:] + self._random_host_data[0:8]
		logger.debug(f"random_host_data__swapped={random_host_data__swapped.hex(':')}")

		self._verify_salt = (
			self.random_device_data[12:12+4]
			+
			self._random_host_data[12:12+4]
			#+
			#self._random_host_data[8:8+8]
		)
		logger.debug(f"self._verify_salt={self._verify_salt.hex(':')}")

		console_id_from_host = decrypted_host_data[0x10:0x10 + 8]
		logger.debug(f"console_id_from_host={console_id_from_host.hex(':')}")
		self._console_id = console_id_from_host

		logger.debug("Deriving DES2 keys from provided console id/cert/data.")
		self.compute_console_keys(console_id_from_host)
		logger.debug(f"Derived DES2 key number 1: {self._xsm3_kv_2des_key_1.hex(':')}")
		logger.debug(f"Derived DES2 key number 1: {self._xsm3_kv_2des_key_2.hex(':')}")

		logger.debug("Encrypting data from host, to prove we have root key 35 (XSM3_ROOT_KEY_0x23).")
		self._proof_0x23 = Xbox360ControllerAuth.des3_encrypt(
			msg=self._random_host_data,
			key=self._xsm3_kv_2des_key_1,
		)
		logger.debug(f"self._proof_0x23={self._proof_0x23.hex(':')}")

		logger.debug("Encrypting data from host, to prove we have root key 36 (XSM3_ROOT_KEY_0x24).")
		self._proof_0x24 = Xbox360ControllerAuth.des3_encrypt(
			msg=random_host_data__swapped,
			key=self._xsm3_kv_2des_key_2,
		)
		logger.debug(f"self._proof_0x24={self._proof_0x24.hex(':')}")

		logger.debug(f"The unencrypted response payload consists of:")
		logger.debug(f"  The random data from the device: {self.random_device_data.hex(':')}")
		logger.debug(f"  The random data from the host:   {self._random_host_data.hex(':')}")
		response_payload__before_encrypting = self.random_device_data + self._random_host_data
		logger.debug(f"response_payload__before_encrypting={response_payload__before_encrypting.hex(':')}")

		## We need the SHA1 hash, as 8 bytes will be used as 
		## IV/salt in the next challenge.
		sha1 = SHA1.new()
		sha1.update(response_payload__before_encrypting)
		self._challenge_response_sha1 = sha1.digest()
		logger.debug(f"self._challenge_response_sha1={self._challenge_response_sha1.hex(':')}")


		logger.debug(f"Encrypting this payload with the 0x23 proof.")
		response_payload__after_encrypting = Xbox360ControllerAuth.des3_encrypt(
			msg=response_payload__before_encrypting,
			key=self._proof_0x23
		)
		logger.debug(f"response_payload__after_encrypting={response_payload__after_encrypting.hex(':')}")

		response_payload__after_encrypting__mac = Xbox360ControllerAuth.MAC(
			key=self._proof_0x24,
			data=response_payload__after_encrypting,
			iv=bytes(8),			## !Zero IV/salt!
		)
		logger.debug(f"response_payload__after_encrypting__mac={response_payload__after_encrypting__mac.hex(':')}")

		acr = self.ACR(
			key=response_payload__after_encrypting__mac,
			input=self._static_device_data,
		)
		logger.debug(f"acr={acr.hex(':')}")

		## Time to create the response.
		xsm3_challenge_response = bytearray(0x2e)
		xsm3_challenge_response[0] = 0x49	## Packet magic
		xsm3_challenge_response[1] = 0x4c
		xsm3_challenge_response[4] = 0x28	## Packet length, 0x28 == 40

		xsm3_challenge_response[5       :5 + 0x20      ] = response_payload__after_encrypting
		xsm3_challenge_response[5 + 0x20:5 + 0x20 + 0x8] = acr

		logger.debug("Challenge response assembled. Computing and storing checksum.")
		cksum = Xbox360ControllerAuth.checksum(xsm3_challenge_response)
		logger.debug(f"cksum={cksum:02x}")

		xsm3_challenge_response[-1] = cksum
		logger.debug(f"xsm3_challenge_response={xsm3_challenge_response.hex(':')}")

		return xsm3_challenge_response


	def parse_challenge_data2(self: Self, data: bytes) -> None:
		header = data[0:5]
		logger.debug(f"header={header.hex(':')}")

		payload = data[5:]
		logger.debug(f"payload={payload.hex(':')}")

		## Split the payload.
		encrypted_data = payload[0:-5]
		logger.debug(f"encrypted_data={encrypted_data.hex(':')}")

		provided_mac = payload[-9:-1]
		logger.debug(f"provided_mac={provided_mac.hex(':')}")

		provided_checksum = payload[-1]
		logger.debug(f"provided_checksum={provided_checksum:02x}")



		## Verify the checksum.
		computed_checksum = Xbox360ControllerAuth.checksum(data)
		logger.debug(f"computed_checksum={computed_checksum:02x}")
		assert provided_checksum == computed_checksum

		## The DES IV is 1 higher than the salt (when using big endian).
		self._verify_salt = struct.pack('>Q', struct.unpack('>Q', self._verify_salt)[0] + 1)
		computed_mac = Xbox360ControllerAuth.MAC(
			data=encrypted_data[0:8],
			#key=DES3_KEY_0x1E,
			key=self._challenge_response_sha1[0:16],
			#iv=bytes(8),
			iv=self._verify_salt[0:8],
		)
		## Verify MAC.
		if provided_mac != computed_mac:
			logger.error(f"Provided MAC ({provided_mac.hex(':')}) and computed MAC ({computed_mac.hex(':')}) differ!")
		else:
			logger.debug(f"Provided MAC ({provided_mac.hex(':')}) and computed MAC ({computed_mac.hex(':')}) match.")
		assert provided_mac == computed_mac

		## Decrypt the encrypted data.
		cipher = DES3.new(
			#key=DES3_KEY_0x1D,
			key=self._random_device_data,
			mode=DES3.MODE_CBC,
			iv=bytes(8),
		)
		decrypted_host_data = cipher.decrypt(payload[0:0x8])
		logger.debug(f"decrypted_host_data={decrypted_host_data.hex(':')}")

		acr = self.ACR(
			key=decrypted_host_data,
			input=self._static_device_data,
		)
		logger.debug(f"acr={acr.hex(':')}")
		response_payload__before_encrypting = acr
		logger.debug(f"response_payload__before_encrypting={response_payload__before_encrypting.hex(':')}")

		logger.debug(f"Encrypting this payload with the 0x23 proof.")
		response_payload__after_encrypting = Xbox360ControllerAuth.des3_encrypt(
			msg=response_payload__before_encrypting,
			key=self._proof_0x23
		)
		logger.debug(f"response_payload__after_encrypting={response_payload__after_encrypting.hex(':')}")

		self._verify_salt = struct.pack('>Q', struct.unpack('>Q', self._verify_salt)[0] + 1)
		response_payload__after_encrypting__mac = Xbox360ControllerAuth.MAC(
			key=self._proof_0x24,
			data=response_payload__after_encrypting,
			#iv=bytes(8),
			iv=self._verify_salt[0:8],
		)
		logger.debug(f"response_payload__after_encrypting__mac={response_payload__after_encrypting__mac.hex(':')}")

		## Time to create the response.
		xsm3_challenge_response = bytearray(0x16)
		xsm3_challenge_response[0] = 0x49	## Packet magic
		xsm3_challenge_response[1] = 0x4c
		xsm3_challenge_response[4] = 0x10	## Packet length, 0x10 == 16

		xsm3_challenge_response[5+0:5+8] = response_payload__after_encrypting
		xsm3_challenge_response[5+8:5+8+8] = response_payload__after_encrypting__mac

		logger.debug("Challenge response assembled. Computing and storing checksum.")
		cksum = Xbox360ControllerAuth.checksum(xsm3_challenge_response)
		logger.debug(f"cksum={cksum:02x}")

		xsm3_challenge_response[-1] = cksum
		logger.debug(f"xsm3_challenge_response={xsm3_challenge_response.hex(':')}")

		return xsm3_challenge_response



	def MAC(data: bytes, key: bytes, iv: bytes) -> bytes:
		logger.debug(f"MAC key={key.hex(':')}")
		logger.debug(f"MAC iv={iv.hex(':')}")
		logger.debug(f"MAC data={data.hex(':')}")

		## Encrypt with DES (not 3DES), use only the last block.
		des_cipher = DES.new(
			key=key[0:8],
			mode=DES.MODE_CBC,
			iv=iv,
		)
		if iv != bytes(8):
			des_cipher.encrypt(bytes(8))
		last_encrypted_block = des_cipher.encrypt(data)[-8:]
		logger.debug(f"last_encrypted_block={last_encrypted_block.hex(':')}")

		## Weird: flip first bit.
		last_encrypted_block_with_msb_flip = (
			bytes([last_encrypted_block[0] ^ 0x80])
			+
			last_encrypted_block[1:8]
		)
		logger.debug(f"last_encrypted_block_with_msb_flip={last_encrypted_block_with_msb_flip.hex(':')}")

		des3_cipher = DES3.new(
			key=key,
			mode=DES.MODE_ECB,
		)
		output = des3_cipher.encrypt(last_encrypted_block_with_msb_flip)
		logger.debug(f"output={output.hex(':')}")
		return output



	def checksum(packet: bytes) -> bytes:
		cksum = 0
		for b in packet[5:-1]:
			cksum ^= b
		return cksum

	def des3_encrypt(msg: bytes, key: bytes) -> bytes:
		cipher = DES3.new(
			key=key,
			mode=DES3.MODE_CBC,
			iv=bytes(8),		## !Zero IV!
		)
		return cipher.encrypt(msg)

	def compute_console_keys(self: Self, console_id: bytes) -> None:
		console_id_hash = SHA1.new()
		console_id_hash.update(console_id)
		console_id_hash = console_id_hash.digest()
		logger.debug(f"console_id_hash={console_id_hash.hex(':')}")

		self._xsm3_kv_2des_key_1 = Xbox360ControllerAuth.des3_encrypt(
			msg=console_id_hash[0:0x10],
			key=XSM3_ROOT_KEY_0x23,
		)
		logger.debug(f"self._xsm3_kv_2des_key_1={self._xsm3_kv_2des_key_1.hex(':')}")

		self._xsm3_kv_2des_key_2 = Xbox360ControllerAuth.des3_encrypt(
			msg=console_id_hash[4:4+0x10],
			key=XSM3_ROOT_KEY_0x24,
		)
		logger.debug(f"self._xsm3_kv_2des_key_2={self._xsm3_kv_2des_key_2.hex(':')}")


	def ACR(self: Self, input: bytes, key: bytes) -> bytes:
		logger.debug("ACR called.")

		console_id = self._console_id
		logger.debug(f"console_id={console_id.hex(':')}")
		logger.debug(f"input={input.hex(':')}")
		logger.debug(f"key={key.hex(':')}")

		block = input[0:4] + console_id[0:4]
		logger.debug(f"block={block.hex(':')}")

		iv = XeCrypt.ParveEcb(
			key=key,
			inp=input[0x10:0x10 + 8],
		)
		logger.debug(f"iv={iv.hex(':')}")

		cd = XeCrypt.ParveEcb(
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

		ab = XeCrypt.ParveCbcMac(
			msg=UsbdSecPlainTextData,
			key=key,
			iv=iv
		)
		logger.debug(f"ab={ab.hex(':')}")

		result = XeCrypt.ChainAndSumMac(cd, ab, UsbdSecPlainTextData)
		return XOR(result, ab)



class XeCrypt:
	def ParveEcb(key: bytes, inp: bytes) -> bytes:
		assert len(key) == 8
		assert len(inp) == 8

		sbox = bytes([
			0xB0, 0x3D, 0x9B, 0x70, 0xF3, 0xC7, 0x80, 0x60,
			0x73, 0x9F, 0x6C, 0xC0, 0xF1, 0x3D, 0xBB, 0x40,
			0xB3, 0xC8, 0x37, 0x14, 0xDF, 0x49, 0xDA, 0xD4,
			0x48, 0x22, 0x78, 0x80, 0x6E, 0xCD, 0xE7, 0x00,
			0x81, 0x86, 0x68, 0xE1, 0x5D, 0x7C, 0x54, 0x2C,
			0x55, 0x7B, 0xEF, 0x48, 0x42, 0x7B, 0x3B, 0x68,
			0xE3, 0xDB, 0xAA, 0xC0, 0x0F, 0xA9, 0x96, 0x20,
			0x95, 0x05, 0x93, 0x94, 0x9A, 0xF6, 0xA3, 0x64,
			0x5D, 0xCC, 0x76, 0x00, 0xE5, 0x08, 0x19, 0xE8,
			0x8D, 0x29, 0xD7, 0x4C, 0x21, 0x91, 0x17, 0xF4,
			0xBC, 0x6A, 0xB3, 0x80, 0x83, 0xC6, 0xD4, 0x90,
			0x9B, 0xAE, 0x0E, 0xFE, 0x2E, 0x4A, 0xF2, 0x00,
			0x73, 0x88, 0xD9, 0x40, 0x66, 0xC5, 0xD4, 0x08,
			0x57, 0xB1, 0x89, 0x48, 0xDC, 0x54, 0xFC, 0x43,
			0x6A, 0x26, 0x87, 0xB8, 0x09, 0x5F, 0xCE, 0x80,
			0xE4, 0x0B, 0x05, 0x9C, 0x24, 0xF3, 0xDE, 0xE2,
			0x3E, 0xEC, 0x38, 0x8A, 0xA2, 0x55, 0xA4, 0x50,
			0x4E, 0x4B, 0xE9, 0x58, 0x7F, 0x9F, 0x7D, 0x80,
			0x23, 0x0C, 0x4D, 0x80, 0x05, 0x44, 0x26, 0xB8,
			0xE9, 0xD8, 0xBC, 0xE6, 0x76, 0x3A, 0x6E, 0xA4,
			0x19, 0xDE, 0xC2, 0xD0, 0xC4, 0xBC, 0xC3, 0x5C,
			0x59, 0xDF, 0x16, 0x46, 0x39, 0x70, 0xF4, 0xEE,
			0x2D, 0x58, 0x5A, 0xA8, 0x17, 0x86, 0x6B, 0x60,
			0x29, 0x58, 0x4D, 0xD2, 0x5F, 0x28, 0x7A, 0xD8,
			0x8E, 0x79, 0xEA, 0x82, 0x94, 0x33, 0x31, 0x81,
			0xD9, 0x22, 0xD5, 0x10, 0xDA, 0x92, 0xA0, 0x7D,
			0x3D, 0xDA, 0xAC, 0x1C, 0xA2, 0x53, 0x31, 0xB8,
			0x3C, 0x96, 0x52, 0x00, 0x82, 0x6B, 0x56, 0xA0,
			0xD3, 0xC2, 0x40, 0xC7, 0x1B, 0x7F, 0xDC, 0x01,
			0x72, 0x70, 0xB1, 0x8C, 0x01, 0x09, 0x09, 0x36,
			0xFC, 0x97, 0xEA, 0xDE, 0xE3, 0x0D, 0xAE, 0x7E,
			0xE3, 0x0D, 0xAE, 0x7E, 0x33, 0x69, 0x80, 0x40,
		])
		def rotl8(x, bits):
			x &= 0xFF
			return ((x << bits) | (x >> (8 - bits))) & 0xFF

		block = bytearray(inp)
		block.append(block[0])	## block[8]

		for i in range(8, 0, -1):
			for j in range(8):
				x = (key[j]  + block[j] + i) & 0xFF
				y = (sbox[x] + block[j + 1]) & 0xFF
				block[j + 1] = rotl8(y, 1)
			block[0] = block[8]

		return bytes(block[:8])



	def ParveCbcMac(msg: bytes, key: bytes, iv: bytes) -> bytes:
		result = iv
		for i in range(len(msg) // 8):
			block = msg[8 * i:8 * (i + 1)]
			result = XOR(block, result)
			result = XeCrypt.ParveEcb(inp=result, key=key)
		return result



	def ChainAndSumMac(cd: bytes, ab: bytes, data: bytes) -> bytes:
		out0 = 0
		out1 = 0

		(ab0, ab1) = struct.unpack(">2I", ab)
		ab0 %= 0x7FFFFFFF
		ab1 %= 0x7FFFFFFF

		(cd0, cd1) = struct.unpack(">2I", cd)
		cd0 %= 0x7FFFFFFF
		cd1 %= 0x7FFFFFFF

		for i in range(0, len(data), 8):
			(v0, v1) = struct.unpack_from(">2I", data, i)

			t = v0 * 0xE79A9C1
			t += out0
			t %= 0x7FFFFFFF
			t *= ab0
			t += ab1
			t %= 0x7FFFFFFF
			out1 += t

			t += v1
			t *= cd0
			t %= 0x7FFFFFFF
			t += cd1
			out0 = t % 0x7FFFFFFF
			out1 += out0

		return struct.pack(">2I", (out0 + ab1) % 0x7FFFFFFF, (out1 + cd1) % 0x7FFFFFFF)



class XOR:
	def __new__(cls, arr1: bytes, arr2: bytes) -> bytes:
		assert len(arr1) == len(arr2)
		## Just xor elementwise.
		return bytes(map(lambda elem: elem[0] ^ elem[1], zip(arr1, arr2)))
