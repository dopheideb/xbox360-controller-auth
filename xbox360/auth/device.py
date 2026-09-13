import logging
logger = logging.getLogger(__name__)
import struct
from   typing import Final, Self, cast
import xbox360.auth.base



class Xbox360ControllerAuth(xbox360.auth.base.AuthBase):
	def __init__(self, *args, **kwargs) -> None:
		super().__init__(*args, **kwargs)
		self.is_ready = False



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
			return self.UsbdSecXSM3SetChallengeProtocolData(
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
			## Just acknowledge the OUT packet. (That's what USB standard dictates.)
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
		checksum = xbox360.auth.base.checksum(payload)

		reply_packet = header + payload + bytes([checksum])
		return reply_packet



	def UsbdSecXSM3SetChallengeProtocolData(
			self: Self,
			setup: bytes,
			data: bytes,
	) -> bytes:
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
		computed_checksum = xbox360.auth.base.checksum(payload)
		logger.debug(f"computed_checksum={computed_checksum:02x}")

		if computed_checksum != provided_checksum:
			logger.error(f"Provided checksum ({provided_checksum:#04x}) and computed checksum ({computed_checksum:#04x}) differ!")
		else:
			logger.debug(f"Provided checksum ({provided_checksum:#04x}) and computed checksum ({computed_checksum:#04x}) match!")
		assert provided_checksum == computed_checksum

		## Only the last 4 bytes of the MAC are actually used. 
		## (The provided MAC is also only 4 bytes.)
		computed_mac = xbox360.auth.base.MAC(
			data=encrypted_data,
			key=xbox360.auth.base.DES3_KEY_0x1E,
			iv=bytes(8),
		)[4:8]
		## Verify MAC.
		if provided_mac != computed_mac:
			logger.error(f"Provided MAC ({provided_mac.hex(':')}) and computed MAC ({computed_mac.hex(':')}) differ!")
		else:
			logger.debug(f"Provided MAC ({provided_mac.hex(':')}) and computed MAC ({computed_mac.hex(':')}) match.")
		assert provided_mac == computed_mac

		## Decrypt the encrypted data.
		random_and_static_console_data = xbox360.auth.base.des3_decrypt(
			msg=encrypted_data,
			key=xbox360.auth.base.DES3_KEY_0x1D,
		)
		logger.debug(f"random_and_static_console_data={random_and_static_console_data.hex(':')}")

		## Set static data before random, because the key 
		## derivation based on the random data, is also based on 
		## the static data. The key derivation of the static 
		## data does _not_ depend on the random data.
		self.static_console_data = random_and_static_console_data[0x10:0x10 + 8]
		logger.debug(f"self.static_console_data={self.static_console_data.hex(':')}")

		self.random_console_data = random_and_static_console_data[0:0x10]
		logger.debug(f"self.random_console_data={self.random_console_data.hex(':')}")

		self.is_ready = True
		return bytes(0)



	def UsbdSecXSM3GetStatus(self: Self, setup: bytes) -> bytes:
		if self.is_ready:
			return b"\x02\00"

		self.is_ready = True
		return b"\x01\x00"



	def UsbdSecXSM3GetResponseVerifyProtocolData(self: Self) -> bytes:
		logger.debug(f"The unencrypted response payload consists of:")
		logger.debug(f"  The random data from the controller: {self.random_controller_data.hex(':')}")
		logger.debug(f"  The random data from the console:    {self.random_console_data.hex(':')}")
		response_payload__before_encrypting = (
			self.random_controller_data
			+
			self.random_console_data
		)
		logger.debug(f"response_payload__before_encrypting={response_payload__before_encrypting.hex(':')}")

		random_host_data__swapped = self.random_console_data[8:] + self.random_console_data[0:8]
		logger.debug(f"random_host_data__swapped={random_host_data__swapped.hex(':')}")

		self.verify_iv = (
			self.random_controller_data[12:12+4]
			+
			self.random_console_data[12:12+4]
		)
		logger.debug(f"self.verify_iv={self.verify_iv.hex(':')}")

		logger.debug("Encrypting data from host, to prove we have root key 35 (XSM3_ROOT_KEY_0x23).")
		derived_category_key0 = xbox360.auth.base.des3_encrypt(
			msg=self.random_console_data,
			key=self.console_encryption_keys[0],
		)

		logger.debug("Encrypting data from host, to prove we have root key 36 (XSM3_ROOT_KEY_0x24).")
		derived_category_key1 = xbox360.auth.base.des3_encrypt(
			msg=random_host_data__swapped,
			key=self.console_encryption_keys[1],
		)
		self.derived_category_key = (derived_category_key0, derived_category_key1)

		## We need the SHA1 hash, as 8 bytes will be used as 
		## IV/salt in the next challenge.
		self.challenge_response_sha1 = xbox360.auth.base.SHA1(msg=response_payload__before_encrypting)
		logger.debug(f"self.challenge_response_sha1={self.challenge_response_sha1.hex(':')}")


		logger.debug(f"Encrypting this payload with the 0x23 proof.")
		response_payload__after_encrypting = xbox360.auth.base.des3_encrypt(
			msg=response_payload__before_encrypting,
			key=self.derived_category_key[0],
		)
		logger.debug(f"response_payload__after_encrypting={response_payload__after_encrypting.hex(':')}")

		response_payload__after_encrypting__mac = xbox360.auth.base.MAC(
			key=self.derived_category_key[1],
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
		header = bytes([
			0x49,		## Magic.
			0x4c,		##
			0x00,
			0x00,
			0x28,		## Payload length, 0x28 == 40. It does not include the checksum.
		])
		payload = response_payload__after_encrypting + acr
		checksum = xbox360.auth.base.checksum(payload)
		logger.debug(f"checksum={checksum:02x}")

		xsm3_challenge_response = header + payload + bytes([checksum])
		logger.debug(f"xsm3_challenge_response={xsm3_challenge_response.hex(':')}")

		return xsm3_challenge_response


	def UsbdSecXSM3SetVerifyProtocolData2(
			self: Self,
			setup: bytes,
			data: bytes,

	) -> bytes:
		""" Decrypt challenge data received from host.

		The Xbox 360 will challenge us, based on encrypted 
		information we receive here. The encrypted data contains:

			1. 8 bytes of pseudo random bytes.

		This function decrypts the received data, verifies the 
		MAC, and stores the decrypted data internally.

		This member is closely related to 
		UsbdSecXSM3SetChallengeProtocolData() in which 
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
		computed_checksum = xbox360.auth.base.checksum(payload)
		logger.debug(f"computed_checksum={computed_checksum:02x}")
		assert provided_checksum == computed_checksum

		computed_mac = xbox360.auth.base.MAC(
			data=encrypted_data,
			key=self.challenge_response_sha1[0:16],
			iv=self.increase_verify_iv(),
		)
		## Verify MAC.
		if provided_mac != computed_mac:
			logger.error(f"Provided MAC ({provided_mac.hex(':')}) and computed MAC ({computed_mac.hex(':')}) differ!")
		else:
			logger.debug(f"Provided MAC ({provided_mac.hex(':')}) and computed MAC ({computed_mac.hex(':')}) match.")
		assert provided_mac == computed_mac

		## Decrypt the encrypted data.
		self.challenge_data = xbox360.auth.base.des3_decrypt(
			msg=encrypted_data,
			key=self.random_controller_data,
		)
		logger.debug(f"self.challenge_data={self.challenge_data.hex(':')}")

		self.is_ready = True
		return bytes(0)



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
			key=self.challenge_data,
			input=self.static_controller_data,
		)
		logger.debug(f"acr={acr.hex(':')}")
		response_payload__before_encrypting = acr
		logger.debug(f"response_payload__before_encrypting={response_payload__before_encrypting.hex(':')}")

		logger.debug(f"Encrypting this payload with the 0x23 proof.")
		response_payload__after_encrypting = xbox360.auth.base.des3_encrypt(
			msg=response_payload__before_encrypting,
			key=self.derived_category_key[0],
		)
		logger.debug(f"response_payload__after_encrypting={response_payload__after_encrypting.hex(':')}")

		response_payload__after_encrypting__mac = xbox360.auth.base.MAC(
			key=self.derived_category_key[1],
			data=response_payload__after_encrypting,
			iv=self.increase_verify_iv(),
		)
		logger.debug(f"response_payload__after_encrypting__mac={response_payload__after_encrypting__mac.hex(':')}")

		payload = (
			response_payload__after_encrypting
			+
			response_payload__after_encrypting__mac
		)
		checksum = bytes([xbox360.auth.base.checksum(payload)])
		## Time to create the response.
		xsm3_challenge_response = header + payload + checksum
		logger.debug(f"xsm3_challenge_response={xsm3_challenge_response.hex(':')}")

		return xsm3_challenge_response
