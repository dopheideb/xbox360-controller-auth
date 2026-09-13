import logging
logger = logging.getLogger(__name__)
import struct
from   typing import Final, Self, cast
import xbox360.auth.base


class Xbox360ConsoleAuth(xbox360.auth.base.AuthBase):
	def __init__(self: Self, *args, **kwargs) -> None:
		super().__init__(*args, **kwargs)
		self._decrypted_host_data = None

	def UsbdSecXSM3GetIdentificationProtocolData(self: Self) -> bytes:
		setup_data = bytes([
			0xc1,		## bmRequestType (IN, vendor, interface)
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
		payload_encrypted = xbox360.auth.base.des3_encrypt(
			msg=payload_unencrypted,
			key=xbox360.auth.base.DES3_KEY_0x1D,
		)
		logger.debug(f"payload_encrypted={payload_encrypted.hex(':')}")

		## Only the last 4 bytes of the computed MAC are used.
		MAC = xbox360.auth.base.MAC(
			data=payload_encrypted,
			key=xbox360.auth.base.DES3_KEY_0x1E,
			iv=bytes(8),
		)[4:]
		assert len(MAC) == 4

		payload = payload_encrypted + MAC
		assert len(payload) == payload_length

		checksum = bytes([xbox360.auth.base.checksum(payload)])
		assert len(checksum) == 1

		packet = setup_data + header + payload + checksum
		return packet



	def UsbdSecXSM3GetStatus(self: Self) -> bytes:
		setup_data = bytes([
			0xc1,		## bmRequestType (IN, vendor, interface)
			0x86,		## bRequest
			0x00, 0x00,	## wValue (0x0000)
			0x03, 0x01,	## wIndex (0x0103)
			0x02, 0x00,	## wLength (0x0002)
		])
		assert len(setup_data) == 8
		logger.debug(f"setup_data={setup_data.hex(':')}")

		return setup_data



	def UsbdSecXSM3GetResponseVerifyProtocolData(self: Self) -> bytes:
		setup_data = bytes([
			0xc1,		## bmRequestType (IN, vendor, interface)
			0x83,		## bRequest
			0x28, 0x5c,	## wValue (0x5c28)
			0x03, 0x01,	## wIndex (0x0103)
			0x2e, 0x00,	## wLength (0x002e)
		])
		assert len(setup_data) == 8
		logger.debug(f"setup_data={setup_data.hex(':')}")

		return setup_data



	def UsbdSecXSM3Unknown(self: Self) -> bytes:
		setup_data = bytes([
			0x41,		## bmRequestType (OUT, vendor, interface)
			0x84,		## bRequest
			0x03, 0x00,	## wValue (0x0003)
			0x03, 0x01,	## wIndex (0x0103)
			0x00, 0x00,	## wLength (0x0000)
		])
		assert len(setup_data) == 8
		logger.debug(f"setup_data={setup_data.hex(':')}")

		return setup_data



	def UsbdSecXSM3SetVerifyProtocolData2(self: Self) -> bytes:
		setup_data = bytes([
			0x41,		## bmRequestType (OUT, vendor, interface)
			0x87,		## bRequest
			0x03, 0x00,	## wValue (0x0003)
			0x03, 0x01,	## wIndex (0x0103)
			0x16, 0x00,	## wLength (0x0016)
		])
		assert len(setup_data) == 8
		logger.debug(f"setup_data={setup_data.hex(':')}")

		header = bytes([
			0x09,
			0x41,
			0x00,
			0x00,
			0x10,		## Payload length.
		])
		encrypted_challenge_data = xbox360.auth.base.des3_encrypt(
			msg=self.challenge_data,
			key=self.random_controller_data,
		)
		mac = xbox360.auth.base.MAC(
			data=encrypted_challenge_data,
			key=self.challenge_response_sha1[0:16],
			iv=self.increase_verify_iv(),
		)
		payload = encrypted_challenge_data + mac
		assert len(payload) == 0x10
		checksum = xbox360.auth.base.checksum(payload)
		packet = setup_data + header + payload + bytes([checksum])
		return packet



	def UsbdSecXSM3GetResponseVerifyProtocolData2(self: Self) -> bytes:
		setup_data = bytes([
			0xc1,		## bmRequestType (IN, vendor, interface)
			0x83,		## bRequest
			0x10, 0x5c,	## wValue (0x5c10)
			0x03, 0x01,	## wIndex (0x0103)
			0x16, 0x00,	## wLength (0x0016)
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

		if reply[1] == 0x4C and reply[4] == 0x28:
			self.parse_UsbdSecXSM3GetResponseVerifyProtocolData_reply(reply)
			return

		if reply[1] == 0x4C and reply[4] == 0x10:
			self.parse_UsbdSecXSM3GetResponseVerifyProtocolData2_reply(reply)
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
		payload_length = 0x28
		header = bytes([
			0x49,
			0x4c,
			0x00,
			0x00,
			payload_length,
		])
		assert reply[0:5] == header

		payload = reply[5:-1]
		assert len(payload) == payload_length, f"The payload must be {payload_length} bytes long, not {len(payload)}."

		provided_checksum = reply[-1]
		computed_checksum = xbox360.auth.base.checksum(
			payload
		)
		logger.debug(f"provided_checksum=0x{provided_checksum:02x}")
		logger.debug(f"computed_checksum=0x{computed_checksum:02x}")
		assert provided_checksum == computed_checksum,\
			f"Checksum mismatch. Computed checksum (0x{computed_checksum:02x}) does not match packet provided checksum (0x{provided_checksum:02x})."

		## The payload consists of 2 parts. Split into those 
		## parts.
		encrypted_message = payload[0:-8]
		provided_acr = payload[-8:]
		logger.debug(f"encrypted_message={encrypted_message.hex(':')}")
		logger.debug(f"provided_acr={provided_acr.hex(':')}")
		assert len(encrypted_message) == 32
		## We can check the ACR once we have calculated the 
		## derived category keys. I.e. we can't check the ACR 
		## right now.

		controller_key = xbox360.auth.base.des3_encrypt(
			msg=self.random_console_data,
			key=self.console_encryption_keys[0],
		)
		logger.debug(f"controller_key={controller_key.hex(':')}")

		logger.debug("Decrypting the encrypted message.")
		decrypted_message = xbox360.auth.base.des3_decrypt(
			msg=encrypted_message,
			key=controller_key,
		)
		logger.debug(f"decrypted_message={decrypted_message.hex(':')}")

		sha1 = xbox360.auth.base.SHA1(msg=decrypted_message)
		self.challenge_response_sha1 = sha1

		## The decrypted message consists of 2 parts. Split into 
		## those parts.
		random_controller_data = decrypted_message[0x00:0x10]
		random_console_data    = decrypted_message[0x10:0x20]
		logger.debug(f"random_controller_data={random_controller_data.hex(':')}")
		logger.debug(f"random_console_data={random_console_data.hex(':')}")

		if self._random_controller_data is None:
			self.random_controller_data = random_controller_data
		else:
			logger.debug(f"Current random controller data: {self.random_controller_data.hex(':')}")
			logger.debug(f"New     random controller data: {random_controller_data.hex(':')}")
			assert self.random_controller_data == random_controller_data

		if self.random_console_data is None:
			self.random_console_data = random_console_data
		else:
			logger.debug(f"Current random console data: {self.random_console_data.hex(':')}")
			logger.debug(f"New     random console data: {random_console_data.hex(':')}")
			assert self.random_console_data == random_console_data

		self.verify_iv = (
			self.random_controller_data[12:12+4]
			+
			self.random_console_data[12:12+4]
		)

		## Check the ACR.
		mac = xbox360.auth.base.MAC(
			key=self.derived_category_key[1],
			data=encrypted_message,
			iv=bytes(8),
		)
		computed_acr = self.ACR(
			key=mac,
			input=self.static_controller_data,
		)
		logger.debug(f"computed_acr={computed_acr.hex(':')}")
		logger.debug(f"provided_acr={provided_acr.hex(':')}")
		assert computed_acr == provided_acr



	def parse_UsbdSecXSM3GetResponseVerifyProtocolData2_reply(self: Self, reply: bytes) -> None:
		payload_length = 0x10
		header = bytes([
			0x49,
			0x4c,
			0x00,
			0x00,
			payload_length,
		])
		assert reply[0:5] == header

		payload = reply[5:-1]
		assert len(payload) == payload_length, f"The payload must be {payload_length} bytes long, not {len(payload)}."

		provided_checksum = reply[-1]
		computed_checksum = xbox360.auth.base.checksum(
			payload
		)
		logger.debug(f"provided_checksum=0x{provided_checksum:02x}")
		logger.debug(f"computed_checksum=0x{computed_checksum:02x}")
		assert provided_checksum == computed_checksum,\
			f"Checksum mismatch. Computed checksum (0x{computed_checksum:02x}) does not match packet provided checksum (0x{provided_checksum:02x})."

		## The payload consists of 2 parts. Split into those 
		## parts.
		encrypted_message = payload[0:-8]
		provided_mac = payload[-8:]
		logger.debug(f"encrypted_message={encrypted_message.hex(':')}")
		logger.debug(f"provided_mac={provided_mac.hex(':')}")
		assert len(encrypted_message) == 8

		## Check the MAC.
		computed_mac = xbox360.auth.base.MAC(
			key=self.derived_category_key[1],
			data=encrypted_message,
			iv=self.increase_verify_iv(),
		)
		logger.debug(f"provided_mac={provided_mac.hex(':')}")
		logger.debug(f"computed_mac={computed_mac.hex(':')}")
		assert computed_mac == provided_mac

		## Decrypt the ACR.
		response_payload__before_encrypting = xbox360.auth.base.des3_decrypt(
			msg=encrypted_message,
			key=self.derived_category_key[0],
		)
		provided_acr = response_payload__before_encrypting
		computed_acr = self.ACR(
			key=self.challenge_data,
			input=self.static_controller_data,
		)
		logger.debug(f"provided_acr={provided_acr.hex(':')}")
		logger.debug(f"computed_acr={computed_acr.hex(':')}")
		assert computed_acr == provided_acr
