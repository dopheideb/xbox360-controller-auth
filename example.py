#!/usr/bin/env python3

import logging
import xbox360controllerauth

#logformat = '%(asctime)s - %(name)s - %(levelname)-5s - %(message)s'
logformat = '%(name)s - %(levelname)-5s - [%(funcName)s] %(message)s'
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



xca = xbox360controllerauth.Xbox360ControllerAuth()
xca.random_controller_data = b"\x58\xf7\xb3\x7a\xef\x4a\x45\xcd\x29\x32\x85\x20\xe9\x26\x10\x3e"

xca.parse_IN_packet(b"\x49\x4b\x00\x00\x17\x4c\x04\x37\x08\x04\x45\x9c\x29\x02\x03\x20\x00\x00\x80\x02\x5e\x04\x8e\x02\x03\x00\x01\x01\xf5")
reply_computed = xca.parse_OUT_packet(b"\x41\x82\x03\x00\x03\x01\x22\x00\x09\x40\x00\x00\x1c\x77\x6f\x34\x2b\x4c\x16\x6e\xc6\xc4\x04\x22\x0f\xf5\x95\x5b\x28\x7d\xa6\xf6\x2a\x3a\x2b\xd8\x32\xee\x1d\x69\x1e\x73")
reply_expected = bytes.fromhex("494c000028657a874e8a14c1a802171c449bacafa7afd56fcd1a7f28ba45b40061a5b968a51e20254cc897fecf04")
logger.debug(f"reply_computed={reply_computed.hex(':')}")
logger.debug(f"reply_expected={reply_expected.hex(':')}")
assert reply_computed == reply_expected

xca.parse_IN_packet(b"\x01\x00")
xca.parse_IN_packet(b"\x01\x00")
xca.parse_IN_packet(b"\x01\x00")
xca.parse_IN_packet(b"\x02\x00")
xca.parse_IN_packet(b"\x49\x4c\x00\x00\x28\x65\x7a\x87\x4e\x8a\x14\xc1\xa8\x02\x17\x1c\x44\x9b\xac\xaf\xa7\xaf\xd5\x6f\xcd\x1a\x7f\x28\xba\x45\xb4\x00\x61\xa5\xb9\x68\xa5\x1e\x20\x25\x4c\xc8\x97\xfe\xcf\x04")
xca.parse_OUT_packet(b"\x41\x84\x03\x00\x03\x01\x00\x00")

out_packet = bytes.fromhex("4187030003011600 09410000100b17a6820787ee8db6ed6a1db3fd01378f")
logger.debug(f"== Handling OUT packet {out_packet.hex(':')}")
reply_computed = xca.parse_OUT_packet(out_packet)
reply_expected = bytes.fromhex("494c000010a5df272b0004aac0b05a5d229d7f906e91")
logger.debug(f"reply_computed={reply_computed.hex(':')}")
logger.debug(f"reply_expected={reply_expected.hex(':')}")
assert reply_computed == reply_expected

out_packet = bytes.fromhex("4187030003011600 0941000010fc602aae28794567950f8e66ac054721d6")
logger.debug(f"== Handling OUT packet {out_packet.hex(':')}")
reply_computed = xca.parse_OUT_packet(out_packet)
reply_expected = bytes.fromhex("494c000010819ed2809fe8a959b588bca72dcbe1f219")
logger.debug(f"reply_computed={reply_computed.hex(':')}")
logger.debug(f"reply_expected={reply_expected.hex(':')}")
assert reply_computed == reply_expected

print(dir(xca))
