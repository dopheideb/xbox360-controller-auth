import Cryptodome.Cipher.DES
import Cryptodome.Cipher.DES3
import Cryptodome.Hash
import Cryptodome.Util.strxor
import logging
logger = logging.getLogger(__name__)
import struct
from   typing import Final, Self, List


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



class Xbox360Authentication:
	def __init__(self: Self) -> None:
		logger.debug(f"DES3_KEY_0x1D={DES3_KEY_0x1D.hex(':')}")
		logger.debug(f"DES3_KEY_0x1E={DES3_KEY_0x1E.hex(':')}")
		self.reset()

	def reset(self: Self) -> None:
		self._static_console_data = None
		self._random_console_data = None

		self._static_controller_data = None
		self._random_controller_data = None

		self._xsm3_kv_2des_key = [None, None]


	@property
	def static_console_data(self: Self) -> bytes:
		return self._static_console_data

	@static_console_data.setter
	def static_console_data(self: Self, data: bytes) -> None:
		required_len = 8
		if len(data) != required_len:
			raise ValueError(f'We need exactly {required_len} bytes, not {len(data)}.')

		logger.debug(f"Setting static_console_data to {data.hex(':')}.")
		self._static_console_data = data

		## (Re)computed the console keys.
		hash = Cryptodome.Hash.SHA1.new()
		hash.update(data)
		digest = hash.digest()

		key0 = Xbox360ControllerAuth.des3_encrypt(
			msg=digest[0:0x10],
			key=XSM3_ROOT_KEY_0x23,
			iv=bytes(8),
		)
		key1 = Xbox360ControllerAuth.des3_encrypt(
			msg=digest[4:4+0x10],
			key=XSM3_ROOT_KEY_0x24,
			iv=bytes(8),
		)

		self._xsm3_kv_2des_key = [ key0, key1 ]
		logger.debug(f"self._xsm3_kv_2des_key[0]={self._xsm3_kv_2des_key[0].hex(':')}")
		logger.debug(f"self._xsm3_kv_2des_key[1]={self._xsm3_kv_2des_key[1].hex(':')}")



	@property
	def random_console_data(self: Self) -> bytes:
		return self._random_console_data

	@random_console_data.setter
	def random_console_data(self: Self, data: bytes) -> None:
		logger.debug(f"data={data.hex(':')}")
		required_len = 16
		if len(data) != required_len:
			raise ValueError(f'We need exactly {required_len} bytes, not {len(data)}.')

		logger.debug(f"Setting random_console_data to {data.hex(':')}.")
		self._random_console_data = data



	@property
	def static_controller_data(self: Self) -> bytes:
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
		return self._random_controller_data

	@random_controller_data.setter
	def random_controller_data(self: Self, data: bytes) -> None:
		required_len = 16
		if len(data) != required_len:
			raise ValueError(f'We need exactly {required_len} bytes, not {len(data)}.')

		logger.debug(f"Setting random_controller_data to {data.hex(':')}.")
		self._random_controller_data = data



	@property
	def console_encryption_keys(self: Self) -> List[bytes]:
		return self._xsm3_kv_2des_key




class Xbox360ConsoleAuth(Xbox360Authentication):
	def __init__(self: Self, *args, **kwargs) -> None:
		super().__init__(*args, **kwargs)
		self._decrypted_host_data = None

	def UsbdSecXSM3GetIdentificationProtocolData(self: Self) -> bytes:
		setup_data = bytes([
			0xc1,		## bmRequestType (OUT, vendor, interface)
			0x81,		## bRequest
			0x17, 0x5b,	## wValue (0x5b17)
			0x03, 0x01,	## wIndex (0x0103)
			0x1d, 0x00,	## wLength (0x001d)
		])
		assert len(setup_data) == 8
		logger.debug(f"setup_data={setup_data.hex(':')}")

		return setup_data



	def UsbdSecXSM3SetChallengeProtocolData(self: Self) -> bytes:
		setup_data = bytes([
			0x41,		## bmRequestType (OUT, vendor, interface)
			0x82,		## bRequest
			0x03, 0x00,	## wValue (0x0003)
			0x03, 0x01,	## wIndex (0x0103)
			0x22, 0x00,	## wLength (0x0022)
		])
		assert len(setup_data) == 8

		payload_length = 0x1c
		header = bytes([
			0x09,
			0x40,
			0x00,
			0x00,
			payload_length,
		])

		payload_unencrypted = (
			self.random_console_data
			+
			self.static_console_data
		)

		## Encrypt the payload.
		cipher = Cryptodome.Cipher.DES3.new(
			key=DES3_KEY_0x1D,
			mode=Cryptodome.Cipher.DES3.MODE_CBC,
			iv=bytes(8),		## !Zero IV!
		)
		payload_encrypted = cipher.encrypt(payload_unencrypted)
		logger.debug(f"payload_encrypted={payload_encrypted.hex(':')}")

		## Only the last 4 bytes of the computed MAC are used.
		MAC = Xbox360ControllerAuth.MAC(
			data=payload_encrypted,
			key=DES3_KEY_0x1E,
			iv=bytes(8),
		)[4:]
		assert len(MAC) == 4

		payload = payload_encrypted + MAC
		assert len(payload) == payload_length

		checksum = bytes([Xbox360ControllerAuth.checksum(payload)])
		assert len(checksum) == 1

		packet = setup_data + header + payload + checksum
		return packet



	def UsbdSecXSM3GetStatus(self: Self) -> bytes:
		setup_data = bytes([
			0xc1,		## bmRequestType (OUT, vendor, interface)
			0x86,		## bRequest
			0x00, 0x00,	## wValue (0x0000)
			0x03, 0x01,	## wIndex (0x0103)
			0x02, 0x00,	## wLength (0x0002)
		])
		assert len(setup_data) == 8
		logger.debug(f"setup_data={setup_data.hex(':')}")

		return setup_data



	def parse_reply(self: Self, reply: bytes) -> None:
		if reply[0] != 0x49:
			raise ValueError(f"All replies start with 0x49, not 0x{reply[0]:02x}.")

		if reply[1] == 0x4B:
			self.parse_UsbdSecXSM3GetIdentificationProtocolData_reply(reply)
			return

		if reply[1] == 0x4C:
			self.parse_UsbdSecXSM3GetResponseVerifyProtocolData_reply(reply)
			return

		raise ValueError(f"Unknown reply {reply.hex(':')}")

	def parse_UsbdSecXSM3GetIdentificationProtocolData_reply(self: Self, reply: bytes) -> None:
		header = bytes([
			0x49,	## Magic
			0x4b,	## Type
			0x00,	##
			0x00,	##
			0x17,	## Length
		])
		assert reply[0:5] == header
		length = reply[4]
		payload = reply[5:-1]
		checksum = reply[-1]
		assert len(payload) == length, f"The header says the payload is {length} bytes, but the payload is actually {len(payload)} bytes long."

		self.static_controller_data = (
			  payload[0x00:0x00 + 0xf]
			+ bytes([0x00])
			+ payload[0x0f:0x0f + 0x2]
			+ payload[0x11:0x11 + 0x2]
			+ payload[0x13:0x13 + 0x1]
			+ payload[0x16:0x16 + 0x1]
			+ payload[0x14:0x14 + 0x2]
		)

	def parse_UsbdSecXSM3GetResponseVerifyProtocolData_reply(self: Self, reply: bytes) -> None:
		header = bytes([
			0x49,
			0x4c,
			0x00,
			0x00,
			0x28,
		])
		assert reply[0:5] == header

		payload = reply[5:-1]
		assert len(payload) == 0x28, f"The payload must be 0x28 bytes long, not {len(payload)}."

		provided_checksum = reply[-1]
		computed_checksum = Xbox360ControllerAuth.checksum(
			payload
		)
		logger.debug(f"provided_checksum=0x{provided_checksum:02x}")
		logger.debug(f"computed_checksum=0x{computed_checksum:02x}")
		assert provided_checksum == computed_checksum,\
			f"Checksum mismatch. Computed checksum (0x{computed_checksum:02x}) does not match packet provided checksum (0x{provided_checksum:02x})."

		## The payload consists of 2 parts. Split into those 
		## parts.
		encrypted_message = payload[0x00:0x20]
		acr               = payload[0x20:0x28]
		logger.debug(f"acr={acr.hex(':')}")
		logger.debug(f"encrypted_message={encrypted_message.hex(':')}")

		controller_key = Xbox360ControllerAuth.des3_encrypt(
			msg=self.random_console_data,
			key=self.console_encryption_keys[0],
			iv=bytes(8),
		)
		logger.debug(f"controller_key={controller_key.hex(':')}")

		logger.debug("Decrypting the encrypted message.")
		decrypted_message = Xbox360ControllerAuth.des3_decrypt(
			msg=encrypted_message,
			key=controller_key,
			iv=bytes(8),
		)
		logger.debug(f"decrypted_message={decrypted_message.hex(':')}")

		## The decrypted message consists of 2 parts. Split into 
		## those parts.
		random_controller_data = decrypted_message[0x00:0x10]
		random_console_data    = decrypted_message[0x10:0x20]
		logger.debug(f"random_controller_data={random_controller_data.hex(':')}")
		logger.debug(f"random_console_data={random_console_data.hex(':')}")

		if self.random_controller_data is None:
			self.random_controller_data = random_controller_data
		else:
			assert self.random_controller_data == random_controller_data

		if self.random_console_data is None:
			self.random_console_data = random_console_data
		else:
			logger.debug(f"Current random console data: {self.random_console_data.hex(':')}")
			logger.debug(f"New     random console data: {random_console_data.hex(':')}")
			assert self.random_console_data == random_console_data



class Xbox360ControllerAuth(Xbox360Authentication):
	def __init__(self, *args, **kwargs) -> None:
		super().__init__(*args, **kwargs)
		self.is_ready = False
		#logger.debug(f"DES3_KEY_0x1D={DES3_KEY_0x1D.hex(':')}")
		#logger.debug(f"DES3_KEY_0x1E={DES3_KEY_0x1E.hex(':')}")
		self._console_id = None
		self._xsm3_kv_2des_key_1 = None
		self._xsm3_kv_2des_key_2 = None
		self.challenge_num = None



	def parse_control_transfer(self, data: bytes) -> bytes:
		logger.debug(f"Parsing control transfer={data.hex(':')}")

		setup_data = data[0:8]
		out_data = data[8:]

		bmRequestType = setup_data[0]
		bRequest = setup_data[1]
		wValue   = struct.unpack('<H', setup_data[2:4])[0]
		wIndex   = struct.unpack('<H', setup_data[4:6])[0]
		wLength  = struct.unpack('<H', setup_data[6:8])[0]

		direction = (bmRequestType & 0b10000000) >> 7
		type      = (bmRequestType & 0b01100000) >> 5
		recipient = (bmRequestType & 0b00011111) >> 0

		logger.debug(f"bmRequestType={bmRequestType:#010b}")
		logger.debug(f"  direction={direction}")
		logger.debug(f"  type={type}")
		logger.debug(f"  recipient={recipient}")
		logger.debug(f"bRequest={bRequest:02x}")
		logger.debug(f"wValue={wValue:02x}")
		logger.debug(f"wIndex={wIndex:02x}")
		logger.debug(f"wLength={wLength:02x}")

		if type != 0b10:
			raise ValueError("Expected a VENDOR control transfer.")

		if recipient != 0b00001:
			raise ValueError("Expected an INTERFACE control transfer.")

		## Handle UsbdSecXSM3GetIdentificationProtocolData.
		if (
				direction == 1		## IN (data from device to host)
				and
				bRequest == 0x81	## 129
				and
				wValue == 0x5b17
				and
				wIndex == 0x0103
				and
				wLength == 0x001d	## 29
		):
			return self.UsbdSecXSM3GetIdentificationProtocolData(
				setup=setup_data,
			)

		## Handle UsbdSecXSM3SetChallengeProtocolData.
		if (
				direction == 0		## OUT (data from host to device)
				and
				bRequest == 0x82	## 130
				and
				wValue == 0x0003
				and
				wIndex == 0x0103
				and
				wLength == 0x0022
		):
			return self.UsbdSecXSM3SetChallengeProtocolData1(
				setup=setup_data,
				data=out_data,
			)

		## Handle UsbdSecXSM3GetResponseVerifyProtocolData.
		if (
				direction == 1		## IN (data from device to host)
				and
				bRequest == 0x83	## 131
				and
				wValue == 0x5c28
				and
				wIndex == 0x0103
				and
				wLength == 0x002E	## 46
		):
			return self.UsbdSecXSM3GetResponseVerifyProtocolData()

		## Handle ?UsbdSecXSM3_OK_something?.
		if (
				direction == 0		## OUT (data from host to device)
				and
				bRequest == 0x84	## 132
				and
				wValue == 0x0003
				and
				wIndex == 0x0103
				and
				wLength == 0x0000
		):
			return bytes(0)

		## Handle UsbdSecXSM3GetStatus.
		if (
				direction == 1		## IN (data from device to host)
				and
				bRequest == 0x86	## 134
				and
				wValue == 0x0000
				and
				wIndex == 0x0103
				and
				wLength == 0x0002
		):
			return self.UsbdSecXSM3GetStatus(
				setup=setup_data,
			)

		## Handle UsbdSecXSM3SetVerifyProtocolData2.
		if (
				direction == 0		## OUT (data from host to device)
				and
				bRequest == 0x87	## 135
				and
				wValue == 0x0003
				and
				wIndex == 0x0103
				and
				wLength == 0x0016
		):
			return self.UsbdSecXSM3SetVerifyProtocolData2(
				setup=setup_data,
				data=out_data,
			)

		## Handle UsbdSecXSM3GetResponseVerifyProtocolData2.
		if (
				direction == 1		## IN (data from device to host)
				and
				bRequest == 0x83	## 131
				and
				wValue == 0x5c10
				and
				wIndex == 0x0103
				and
				wLength == 0x0016
		):
			return self.UsbdSecXSM3GetResponseVerifyProtocolData2(
				setup=setup_data,
			)

		raise ValueError(f"Unknown control transfer {data.hex(':')}")



	def UsbdSecXSM3GetIdentificationProtocolData(
			self: Self,
			setup: bytes,
	) -> bytes:
		## This is always the first packet of the authentication 
		## process, so reset the challenge counter.
		self.challenge_num = 0

		header = bytes([
			0x49,	## ?Magic constant?
			0x4b,
			0x00,
			0x00,
			0x17,	## Length of payload (23), does not include checksum byte.
		])
		payload = (
			  self.static_controller_data[0x00:0x00 + 0xf]	## [0x00..0x0e]
			+ self.static_controller_data[0x10:0x10 + 0x2]	## [0x0f..0x10]
			+ self.static_controller_data[0x12:0x12 + 0x2]	## [0x11..0x12]
			+ self.static_controller_data[0x14:0x14 + 0x1]	## [0x13..0x13]
			+ self.static_controller_data[0x16:0x16 + 0x2]	## [0x14..0x15]
			+ self.static_controller_data[0x15:0x15 + 0x1]	## [0x16..0x16]
		)
		checksum = Xbox360ControllerAuth.checksum(payload)

		reply_packet = header + payload + bytes([checksum])
		return reply_packet



	def UsbdSecXSM3SetChallengeProtocolData1(
			self: Self,
			setup: bytes,
			data: bytes,
	) -> None:
		""" Decrypt challenge data received from host.

		The Xbox 360 will challenge us, based on encrypted 
		information we receive here. The encrypted data contains:

			1. 16 pseudo random bytes.
			2. 8 bytes of static data.

		The static data is the same when queried by the same 
		Xbox, but differs when switching to another 360.

		This function decrypts the received data, verifies the 
		MAC, and stores the static and random data.
		"""
		self.is_ready = False

		header = data[0:5]
		payload = data[5:-1]
		provided_checksum = data[-1]

		logger.debug(f"data={data.hex(':')}")
		logger.debug(f"header={header.hex(':')}")
		logger.debug(f"payload={payload.hex(':')}")
		logger.debug(f"provided_checksum={provided_checksum:02x}")
		assert header == bytes([
			0x09,
			0x40,
			0x00,
			0x00,
			0x1c,
		])
		assert len(payload) == 0x1c

		## Split the payload:
		##   - encrypted data (24 bytes)
		##   - MAC (4 bytets)
		encrypted_data = payload[0:-4]
		logger.debug(f"encrypted_data={encrypted_data.hex(':')}")
		assert len(encrypted_data) == 16 + 8

		provided_mac = payload[-4:]
		logger.debug(f"provided_mac={provided_mac.hex(':')}")

		## Verify the checksum.
		computed_checksum = Xbox360ControllerAuth.checksum(payload)
		logger.debug(f"computed_checksum={computed_checksum:02x}")

		if computed_checksum != provided_checksum:
			logger.error(f"Provided checksum ({provided_checksum:#04x}) and computed checksum ({computed_checksum:#04x}) differ!")
		else:
			logger.debug(f"Provided checksum ({provided_checksum:#04x}) and computed checksum ({computed_checksum:#04x}) match!")
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
		cipher = Cryptodome.Cipher.DES3.new(
			key=DES3_KEY_0x1D,
			mode=Cryptodome.Cipher.DES3.MODE_CBC,
			iv=bytes(8),		## !Zero IV!
		)
		self._decrypted_host_data = cipher.decrypt(encrypted_data)
		logger.debug(f"_decrypted_host_data={self._decrypted_host_data.hex(':')}")

		self.random_console_data = self._decrypted_host_data[0:0x10]
		logger.debug(f"self.random_console_data={self.random_console_data.hex(':')}")

		self.static_console_data = self._decrypted_host_data[0x10:0x10 + 8]
		logger.debug(f"self.static_console_data={self.static_console_data.hex(':')}")

		self.is_ready = True



	def UsbdSecXSM3GetStatus(self: Self, setup: bytes) -> bytes:
		if self.is_ready:
			return b"\x02\00"

		self.is_ready = True
		return b"\x01\x00"



	def UsbdSecXSM3GetResponseVerifyProtocolData(self: Self) -> bytes:
		response_payload__before_encrypting = (
			self.random_controller_data
			+
			self.random_console_data
		)
		logger.debug(f"response_payload__before_encrypting={response_payload__before_encrypting.hex(':')}")

		random_host_data__swapped = self.random_console_data[8:] + self.random_console_data[0:8]
		logger.debug(f"random_host_data__swapped={random_host_data__swapped.hex(':')}")

		self._verify_salt = (
			self.random_controller_data[12:12+4]
			+
			self.random_console_data[12:12+4]
		)
		logger.debug(f"self._verify_salt={self._verify_salt.hex(':')}")

		logger.debug("Encrypting data from host, to prove we have root key 35 (XSM3_ROOT_KEY_0x23).")
		self._proof_0x23 = Xbox360ControllerAuth.des3_encrypt(
			msg=self._random_console_data,
			key=self.console_encryption_keys[0],
			iv=bytes(8),
		)
		logger.debug(f"self._proof_0x23={self._proof_0x23.hex(':')}")

		logger.debug("Encrypting data from host, to prove we have root key 36 (XSM3_ROOT_KEY_0x24).")
		self._proof_0x24 = Xbox360ControllerAuth.des3_encrypt(
			msg=random_host_data__swapped,
			key=self.console_encryption_keys[1],
			iv=bytes(8),
		)
		logger.debug(f"self._proof_0x24={self._proof_0x24.hex(':')}")

		logger.debug(f"The unencrypted response payload consists of:")
		logger.debug(f"  The random data from the controller: {self.random_controller_data.hex(':')}")
		logger.debug(f"  The random data from the console:    {self.random_console_data.hex(':')}")
		response_payload__before_encrypting = (
			self.random_controller_data
			+
			self.random_console_data
		)
		logger.debug(f"response_payload__before_encrypting={response_payload__before_encrypting.hex(':')}")

		## We need the SHA1 hash, as 8 bytes will be used as 
		## IV/salt in the next challenge.
		sha1 = Cryptodome.Hash.SHA1.new()
		sha1.update(response_payload__before_encrypting)
		self._challenge_response_sha1 = sha1.digest()
		logger.debug(f"self._challenge_response_sha1={self._challenge_response_sha1.hex(':')}")


		logger.debug(f"Encrypting this payload with the 0x23 proof.")
		response_payload__after_encrypting = Xbox360ControllerAuth.des3_encrypt(
			msg=response_payload__before_encrypting,
			key=self._proof_0x23,
			iv=bytes(8),
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
			input=self.static_controller_data,
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
		checksum = Xbox360ControllerAuth.checksum(xsm3_challenge_response[5:-1])
		logger.debug(f"checksum={checksum:02x}")

		xsm3_challenge_response[-1] = checksum
		logger.debug(f"xsm3_challenge_response={xsm3_challenge_response.hex(':')}")

		return xsm3_challenge_response


	def UsbdSecXSM3SetVerifyProtocolData2(
			self: Self,
			setup: bytes,
			data: bytes,

	) -> None:
		""" Decrypt challenge data received from host.

		The Xbox 360 will challenge us, based on encrypted 
		information we receive here. The encrypted data contains:

			1. 8 bytes of pseudo random bytes.

		This function decrypts the received data, verifies the 
		MAC, and stores the decrypted data internally.

		This member is closely related to 
		UsbdSecXSM3SetChallengeProtocolData1() in which 
		calculations are made, yet differ in terms like 3DES key.
		"""
		self.is_ready = False

		header = data[0:5]
		payload = data[5:-1]
		provided_checksum = data[-1]

		logger.debug(f"data={data.hex(':')}")
		logger.debug(f"header={header.hex(':')}")
		logger.debug(f"payload={payload.hex(':')}")
		logger.debug(f"provided_checksum={provided_checksum:02x}")
		assert header == bytes([
			0x09,
			0x41,
			0x00,
			0x00,
			0x10,
		])
		assert len(payload) == 0x10

		## Split the payload:
		##   encypted data (8 bytes)
		##   MAC (8 bytes)
		encrypted_data = payload[0:8]
		logger.debug(f"encrypted_data={encrypted_data.hex(':')}")

		provided_mac = payload[-8:]
		logger.debug(f"provided_mac={provided_mac.hex(':')}")



		## Verify the checksum.
		computed_checksum = Xbox360ControllerAuth.checksum(payload)
		logger.debug(f"computed_checksum={computed_checksum:02x}")
		assert provided_checksum == computed_checksum

		## The DES IV is 1 higher than the salt (when using big 
		## endian).
		self._verify_salt = struct.pack(
			'>Q',
			1 + struct.unpack('>Q', self._verify_salt)[0],
		)
		computed_mac = Xbox360ControllerAuth.MAC(
			data=encrypted_data,
			#key=DES3_KEY_0x1E,
			key=self._challenge_response_sha1[0:16],
			iv=self._verify_salt,
		)
		## Verify MAC.
		if provided_mac != computed_mac:
			logger.error(f"Provided MAC ({provided_mac.hex(':')}) and computed MAC ({computed_mac.hex(':')}) differ!")
		else:
			logger.debug(f"Provided MAC ({provided_mac.hex(':')}) and computed MAC ({computed_mac.hex(':')}) match.")
		assert provided_mac == computed_mac

		## Decrypt the encrypted data.
		cipher = Cryptodome.Cipher.DES3.new(
			#key=DES3_KEY_0x1D,
			key=self._random_controller_data,
			mode=Cryptodome.Cipher.DES3.MODE_CBC,
			iv=bytes(8),
		)
		self._decrypted_host_data = cipher.decrypt(encrypted_data)
		logger.debug(f"_decrypted_host_data={self._decrypted_host_data.hex(':')}")

		self.is_ready = True



	def UsbdSecXSM3GetResponseVerifyProtocolData2(
			self: Self,
			setup: bytes,
	) -> bytes:
		payload_length = 0x10
		header = bytes([
			0x49,		## Magic
			0x4c,
			0x00,
			0x00,
			payload_length,
		])

		acr = self.ACR(
			key=self._decrypted_host_data,
			input=self._static_controller_data,
		)
		logger.debug(f"acr={acr.hex(':')}")
		response_payload__before_encrypting = acr
		logger.debug(f"response_payload__before_encrypting={response_payload__before_encrypting.hex(':')}")

		logger.debug(f"Encrypting this payload with the 0x23 proof.")
		response_payload__after_encrypting = Xbox360ControllerAuth.des3_encrypt(
			msg=response_payload__before_encrypting,
			key=self._proof_0x23,
			iv=bytes(8),
		)
		logger.debug(f"response_payload__after_encrypting={response_payload__after_encrypting.hex(':')}")

		self._verify_salt = struct.pack(
			'>Q',
			1 + struct.unpack('>Q', self._verify_salt)[0],
		)
		response_payload__after_encrypting__mac = Xbox360ControllerAuth.MAC(
			key=self._proof_0x24,
			data=response_payload__after_encrypting,
			iv=self._verify_salt,
		)
		logger.debug(f"response_payload__after_encrypting__mac={response_payload__after_encrypting__mac.hex(':')}")

		payload = (
			response_payload__after_encrypting
			+
			response_payload__after_encrypting__mac
		)
		checksum = bytes([Xbox360ControllerAuth.checksum(payload)])
		## Time to create the response.
		xsm3_challenge_response = header + payload + checksum
		logger.debug(f"xsm3_challenge_response={xsm3_challenge_response.hex(':')}")

		return xsm3_challenge_response



	def MAC(data: bytes, key: bytes, iv: bytes) -> bytes:
		logger.debug(f"MAC key={key.hex(':')}")
		logger.debug(f"MAC iv={iv.hex(':')}")
		logger.debug(f"MAC data={data.hex(':')}")

		## Encrypt with DES (not 3DES), use only the last block.
		des_cipher = Cryptodome.Cipher.DES.new(
			key=key[0:8],
			mode=Cryptodome.Cipher.DES.MODE_CBC,
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

		des3_cipher = Cryptodome.Cipher.DES3.new(
			key=key,
			mode=Cryptodome.Cipher.DES.MODE_ECB,
		)
		output = des3_cipher.encrypt(last_encrypted_block_with_msb_flip)
		logger.debug(f"output={output.hex(':')}")
		return output



	def checksum(data: bytes) -> bytes:
		logger.debug(f"Calculating checksum over {data.hex(':')}.")
		cksum = 0
		for byte in data:
			cksum ^= byte
		logger.debug(f"Checksum over {data.hex(':')} is {cksum:#04x}.")
		return cksum

	def des3_decrypt(msg: bytes, key: bytes, iv: bytes) -> bytes:
		cipher = Cryptodome.Cipher.DES3.new(
			key=key,
			mode=Cryptodome.Cipher.DES3.MODE_CBC,
			iv=iv,
		)
		return cipher.decrypt(msg)

	def des3_encrypt(msg: bytes, key: bytes, iv: bytes) -> bytes:
		cipher = Cryptodome.Cipher.DES3.new(
			key=key,
			mode=Cryptodome.Cipher.DES3.MODE_CBC,
			iv=iv,
		)
		return cipher.encrypt(msg)

	def compute_console_keys(self: Self, console_id: bytes) -> None:
		console_id_hash = Cryptodome.Hash.SHA1.new()
		console_id_hash.update(console_id)
		console_id_hash = console_id_hash.digest()
		logger.debug(f"console_id_hash={console_id_hash.hex(':')}")

		self._xsm3_kv_2des_key_1 = Xbox360ControllerAuth.des3_encrypt(
			msg=console_id_hash[0:0x10],
			key=XSM3_ROOT_KEY_0x23,
			iv=bytes(8)
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
		logger.debug(f"self.static_console_data={self.static_console_data.hex(':')}")
		logger.debug(f"input={input.hex(':')}")
		logger.debug(f"key={key.hex(':')}")

		block = input[0:4] + self.static_console_data[0:4]
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
		return Cryptodome.Util.strxor.strxor(
			term1=result,
			term2=ab,
			output=None
		)



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
			result = Cryptodome.Util.strxor.strxor(
				term1=block,
				term2=result,
				output=None
			)
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
