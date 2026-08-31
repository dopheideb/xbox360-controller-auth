#!/usr/bin/env python3

import logging
import time
import xbox360controllerauth

logformat = '%(levelname)-5s [%(filename)s:%(funcName)s:%(lineno)s] %(message)s'
formatter = logging.Formatter(logformat)

handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

def enable_module_logging(module_name, level=logging.DEBUG):
	module_logger = logging.getLogger(module_name)
	module_logger.setLevel(level)
	module_logger.addHandler(handler)
	return module_logger
logger = enable_module_logging(__name__)
enable_module_logging('xbox360controllerauth')


console = xbox360controllerauth.Xbox360ConsoleAuth()
console.static_console_data = bytes.fromhex("06 47 2b 2b 09 80 81 82")
console.random_console_data = bytes.fromhex("57 50 02 e6 ea 6f 1a 2d d4 45 21 89 fd 9c 87 db")

controller = xbox360controllerauth.Xbox360ControllerAuth()
controller.static_controller_data = bytes.fromhex("4c 04 37 08 04 45 9c 29 02 03 20 00 00 80 02 5e 04 8e 02 03 00 01 01 00")
controller.random_controller_data = bytes.fromhex("58 f7 b3 7a ef 4a 45 cd 29 32 85 20 e9 26 10 3e")



## The console requests the static/identification data from the controller.
UsbdSecXSM3GetIdentificationProtocolData_console2controller_computed = console.UsbdSecXSM3GetIdentificationProtocolData()
UsbdSecXSM3GetIdentificationProtocolData_console2controller_expected = bytes.fromhex("c1 81 17 5b 03 01 1d 00")
logger.debug(f"UsbdSecXSM3GetIdentificationProtocolData_console2controller_computed={UsbdSecXSM3GetIdentificationProtocolData_console2controller_computed.hex(':')}")
logger.debug(f"UsbdSecXSM3GetIdentificationProtocolData_console2controller_expected={UsbdSecXSM3GetIdentificationProtocolData_console2controller_expected.hex(':')}")
assert UsbdSecXSM3GetIdentificationProtocolData_console2controller_computed == UsbdSecXSM3GetIdentificationProtocolData_console2controller_expected

## The controller answers with the static/identification data.
UsbdSecXSM3GetIdentificationProtocolData_controller2console_computed = controller.parse_control_transfer(UsbdSecXSM3GetIdentificationProtocolData_console2controller_computed)
UsbdSecXSM3GetIdentificationProtocolData_controller2console_expected = bytes.fromhex("49 4b 00 00 17 4c 04 37 08 04 45 9c 29 02 03 20 00 00 80 02 5e 04 8e 02 03 00 01 01 f5")
logger.debug(f"UsbdSecXSM3GetIdentificationProtocolData_controller2console_computed={UsbdSecXSM3GetIdentificationProtocolData_controller2console_computed.hex(':')}")
logger.debug(f"UsbdSecXSM3GetIdentificationProtocolData_controller2console_expected={UsbdSecXSM3GetIdentificationProtocolData_controller2console_expected.hex(':')}")

assert UsbdSecXSM3GetIdentificationProtocolData_controller2console_computed == UsbdSecXSM3GetIdentificationProtocolData_controller2console_expected


console.random_controller_data = bytes.fromhex("58 f7 b3 7a ef 4a 45 cd 29 32 85 20 e9 26 10 3e")

## The console gives static and random console data.
UsbdSecXSM3SetChallengeProtocolData_console2controller_computed = console.UsbdSecXSM3SetChallengeProtocolData()
UsbdSecXSM3SetChallengeProtocolData_console2controller_expected = bytes.fromhex("41 82 03 00 03 01 22 00   09 40 00 00 1c 77 6f 34 2b 4c 16 6e c6 c4 04 22 0f f5 95 5b 28 7d a6 f6 2a 3a 2b d8 32 ee 1d 69 1e 73")
logger.debug(f"UsbdSecXSM3SetChallengeProtocolData_console2controller_computed={UsbdSecXSM3SetChallengeProtocolData_console2controller_computed.hex(':')}")
logger.debug(f"UsbdSecXSM3SetChallengeProtocolData_console2controller_expected={UsbdSecXSM3SetChallengeProtocolData_console2controller_expected.hex(':')}")
assert UsbdSecXSM3SetChallengeProtocolData_console2controller_computed == UsbdSecXSM3SetChallengeProtocolData_console2controller_expected


UsbdSecXSM3SetChallengeProtocolData_controller2console_computed = controller.parse_control_transfer(UsbdSecXSM3SetChallengeProtocolData_console2controller_computed)
UsbdSecXSM3SetChallengeProtocolData_controller2console_expected = None
assert UsbdSecXSM3SetChallengeProtocolData_controller2console_computed == UsbdSecXSM3SetChallengeProtocolData_controller2console_expected



while True:
	UsbdSecXSM3GetStatus_console2controller_computed = console.UsbdSecXSM3GetStatus()
	UsbdSecXSM3GetStatus_console2controller_expected = bytes.fromhex("c1 86 00 00 03 01 02 00")
	logger.debug(f"UsbdSecXSM3GetStatus_console2controller_computed={UsbdSecXSM3GetStatus_console2controller_computed.hex(':')}")
	logger.debug(f"UsbdSecXSM3GetStatus_console2controller_expected={UsbdSecXSM3GetStatus_console2controller_expected.hex(':')}")
	assert UsbdSecXSM3GetStatus_console2controller_computed == UsbdSecXSM3GetStatus_console2controller_expected

	UsbdSecXSM3GetStatus_controller2console_computed = controller.parse_control_transfer(UsbdSecXSM3GetStatus_console2controller_computed)
	logger.debug(f"UsbdSecXSM3GetStatus_controller2console_computed={UsbdSecXSM3GetStatus_controller2console_computed.hex(':')}")
	if UsbdSecXSM3GetStatus_controller2console_computed == b"\x01\x00":
		logger.debug("The controller is still busy.")
		time.sleep(.1)
		continue

	if UsbdSecXSM3GetStatus_controller2console_computed == b"\x02\x00":
		logger.debug("The controller is ready.")
		break

	raise ValueError(f"Unknown status received from controller ({UsbdSecXSM3GetStatus_controller2console_computed.hex(':')})")


controller.parse_IN_packet(b"\x49\x4b\x00\x00\x17\x4c\x04\x37\x08\x04\x45\x9c\x29\x02\x03\x20\x00\x00\x80\x02\x5e\x04\x8e\x02\x03\x00\x01\x01\xf5")
reply_computed = controller.parse_OUT_packet(b"\x41\x82\x03\x00\x03\x01\x22\x00\x09\x40\x00\x00\x1c\x77\x6f\x34\x2b\x4c\x16\x6e\xc6\xc4\x04\x22\x0f\xf5\x95\x5b\x28\x7d\xa6\xf6\x2a\x3a\x2b\xd8\x32\xee\x1d\x69\x1e\x73")
reply_expected = bytes.fromhex("494c000028657a874e8a14c1a802171c449bacafa7afd56fcd1a7f28ba45b40061a5b968a51e20254cc897fecf04")
logger.debug(f"reply_computed={reply_computed.hex(':')}")
logger.debug(f"reply_expected={reply_expected.hex(':')}")
assert reply_computed == reply_expected

controller.parse_IN_packet(b"\x01\x00")
controller.parse_IN_packet(b"\x01\x00")
controller.parse_IN_packet(b"\x01\x00")
controller.parse_IN_packet(b"\x02\x00")
controller.parse_IN_packet(b"\x49\x4c\x00\x00\x28\x65\x7a\x87\x4e\x8a\x14\xc1\xa8\x02\x17\x1c\x44\x9b\xac\xaf\xa7\xaf\xd5\x6f\xcd\x1a\x7f\x28\xba\x45\xb4\x00\x61\xa5\xb9\x68\xa5\x1e\x20\x25\x4c\xc8\x97\xfe\xcf\x04")
controller.parse_OUT_packet(b"\x41\x84\x03\x00\x03\x01\x00\x00")

out_packet = bytes.fromhex("4187030003011600 09410000100b17a6820787ee8db6ed6a1db3fd01378f")
logger.debug(f"== Handling OUT packet {out_packet.hex(':')}")
reply_computed = controller.parse_OUT_packet(out_packet)
reply_expected = bytes.fromhex("494c000010a5df272b0004aac0b05a5d229d7f906e91")
logger.debug(f"reply_computed={reply_computed.hex(':')}")
logger.debug(f"reply_expected={reply_expected.hex(':')}")
assert reply_computed == reply_expected

out_packet = bytes.fromhex("4187030003011600 0941000010fc602aae28794567950f8e66ac054721d6")
logger.debug(f"== Handling OUT packet {out_packet.hex(':')}")
reply_computed = controller.parse_OUT_packet(out_packet)
reply_expected = bytes.fromhex("494c000010819ed2809fe8a959b588bca72dcbe1f219")
logger.debug(f"reply_computed={reply_computed.hex(':')}")
logger.debug(f"reply_expected={reply_expected.hex(':')}")
assert reply_computed == reply_expected
