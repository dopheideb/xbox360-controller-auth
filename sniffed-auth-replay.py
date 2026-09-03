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
controller = xbox360controllerauth.Xbox360ControllerAuth()

lego_dimenions_toypad =\
{
    'static_console_data': bytes.fromhex("06 47 2b 2b 09 80 81 82"),
    'random_console_data': None,

    'static_controller_data': None,
    'random_controller_data': None,

    'UsbdSecXSM3GetIdentificationProtocolData':
    {
        'packet': bytes.fromhex("c1 81 17 5b 03 01 1d 00"),
        'response': bytes.fromhex((
            "49 4b 00 00 17"		## Header. 0x17 == 23
            "74 ff 25 53 0e 11 85 25"	## Payload[0:8]
            "38 03 20 00 00 80 82 c6"	## Payload[8:16]
            "24 00 50 03 00 01 01"	## Payload[16:23]
            "ea"			## Checksum.
        )),
    },



    ##
    ## Challenge 1: Set the challenge.
    ##
    'UsbdSecXSM3SetChallengeProtocolData':
    {
        'packet': bytes.fromhex((
            "41 82 03 00 03 01 22 00"	## Setup data.
            "09 40 00 00 1c"		## Header. 0x1c == 28
            "b6 9e e4 d8 f7 25 22 2c"	## Payload[0:8]
            "d8 d6 d2 52 25 5c 79 bb"	## Payload[8:16]
            "26 4c fd e5 5b be 5b b3"	## Payload[16:24]
            "c8 5a 0e d7"		## Payload[24:28]
            "c9"			## Checksum.
        )),
        'response': bytes(0),
    },

    ##
    ## Challenge 1: Obtain the challenge answer.
    ##
    'UsbdSecXSM3GetResponseVerifyProtocolData1':
    {
        'packet': bytes.fromhex("c1 83 28 5c 03 01 2e 00"),
        'response': bytes.fromhex((
            "49 4c 00 00 28"		## Header. 0x28 == 40
            "b7 7e aa c6 5b 1e 9f cb"	## Payload[0:8]
            "18 25 73 c1 ef 87 5f 7c"	## Payload[8:16]
            "4b 97 6f 65 27 8b d0 c7"	## Payload[16:24]
            "6f 94 f1 b9 7e 6e 65 92"	## Payload[24:32]
            "72 59 15 31 b9 ca 35 5d"	## Payload[32:40]
            "5d"			## Checksum.
        )),
    },



    ##
    ## Challenge 2: Set the challenge.
    ##
    'UsbdSecXSM3SetVerifyProtocolData2':
    {
        'packet': bytes.fromhex((
            "41 87 03 00 03 01 16 00"	## Setup data.
            "09 41 00 00 10"		## Header. 0x10 == 16
            "06 33 fb 2e 1d 5b de 3a"	## Payload[0:8]
            "d9 7c 86 27 1e 0f 3a c7"	## Payload[8:16]
            "aa"			## Checksum.
        )),
        'response': bytes(0),
    },

    ##
    ## Challenge 2: Obtain the challenge answer.
    ##
    'UsbdSecXSM3GetResponseVerifyProtocolData2':
    {
        'packet': bytes.fromhex("c1 83 10 5c 03 01 16 00"),
        'response': bytes.fromhex((
            "49 4c 00 00 10"		## Header. 0x10 == 16
            "18 19 25 45 ad f5 48 f3"	## Payload[0:8]
            "20 f7 87 e0 3f 9f 9d da"	## Payload[8:16]
            "d5"			## Checksum.
        )),
    },



    ##
    ## Challenge 3: Set the challenge.
    ##
    'UsbdSecXSM3SetVerifyProtocolData3':
    {
        'packet': bytes.fromhex((
            "41 87 03 00 03 01 16 00"	## Setup data.
            "09 41 00 00 10"		## Header. 0x10 == 16
            "3e 60 c2 13 bb 02 d8 6c"	## Payload[0:8]
            "d2 02 86 91 aa 3d 8d 8c"	## Payload[8:16]
            "d3"			## Checksum.
        )),
    },

    ##
    ## Challenge 3: Obtain the challenge answer.
    ##
    'UsbdSecXSM3GetResponseVerifyProtocolData3':
    {
        'packet': bytes.fromhex("c1 83 10 5c 03 01 16 00"),
        'response': bytes.fromhex((
            "49 4c 00 00 10"		## Header. 0x10 == 16
            "47 47 98 fa 3f e2 2d 0f"	## Payload[0:8]
            "96 f0 db 2b 6c 4d 78 d5"	## Payload[8:16]
            "87"			## Checksum.
        )),
    },

}

genuine_controller =\
{
    'static_console_data': bytes.fromhex("06 47 2b 2b 09 80 81 82"),
    'random_console_data': bytes.fromhex("57 50 02 e6 ea 6f 1a 2d d4 45 21 89 fd 9c 87 db"),

    'static_controller_data': bytes.fromhex("4c 04 37 08 04 45 9c 29 02 03 20 00 00 80 02 00 5e 04 8e 02 03 01 00 01"),
    'random_controller_data': bytes.fromhex("58 f7 b3 7a ef 4a 45 cd 29 32 85 20 e9 26 10 3e"),

    'UsbdSecXSM3GetIdentificationProtocolData':\
    {
        'packet': bytes.fromhex("c1 81 17 5b 03 01 1d 00"),
        'response': bytes.fromhex("49 4b 00 00 17 4c 04 37   08 04 45 9c 29 02 03 20   00 00 80 02 5e 04 8e 02   03 00 01 01 f5"),
    },



    ##
    ## Challenge 1: Set the challenge.
    ##
    'UsbdSecXSM3SetChallengeProtocolData':
    {
        'packet': bytes.fromhex("41 82 03 00 03 01 22 00   09 40 00 00 1c 77 6f 34   2b 4c 16 6e c6 c4 04 22   0f f5 95 5b 28 7d a6 f6   2a 3a 2b d8 32 ee 1d 69   1e 73"),
        'response': bytes(0),
    },

    ##
    ## Challenge 1: Obtain the challenge answer.
    ##
    'UsbdSecXSM3GetResponseVerifyProtocolData1':
    {
        'packet': bytes.fromhex("c1 83 28 5c 03 01 2e 00"),
        'response': bytes.fromhex((
            "49 4c 00 00 28 65 7a 87"
            "4e 8a 14 c1 a8 02 17 1c"
            "44 9b ac af a7 af d5 6f"
            "cd 1a 7f 28 ba 45 b4 00"
            "61 a5 b9 68 a5 1e 20 25"
            "4c c8 97 fe cf 04"
        )),
    },



    ##
    ## Challenge 2: Set the challenge.
    ##
    'UsbdSecXSM3SetVerifyProtocolData2':
    {
        'packet': bytes.fromhex((
            "41 87 03 00 03 01 16 00"	## Setup data.
            "09 41 00 00 10"		## Header. 0x10 == 16
            "0b 17 a6 82 07 87 ee 8d"	## Payload[0:8].
            "b6 ed 6a 1d b3 fd 01 37"	## Payload[0:16].
            "8f"			## Checksum.
        )),
        'response': bytes(0),
    },

    ##
    ## Challenge 2: Obtain the challenge answer.
    ##
    'UsbdSecXSM3GetResponseVerifyProtocolData2':
    {
        'packet': bytes.fromhex("c1 83 10 5c 03 01 16 00"),
        'response': bytes.fromhex((
            "49 4c 00 00 10"		## Header. 0x10 == 16
            "a5 df 27 2b 00 04 aa c0"	## Payload[0:8].
            "b0 5a 5d 22 9d 7f 90 6e"	## Payload[8:16].
            "91"			## Checksum.
        )),
    },



    ##
    ## Challenge 3: Set the challenge.
    ##
    'UsbdSecXSM3SetVerifyProtocolData3':
    {
        'packet': bytes.fromhex((
            "41 87 03 00 03 01 16 00"	## Setup data.
            "09 41 00 00 10"		## Header. 0x10 == 16
            "fc 60 2a ae 28 79 45 67"	## Payload[0:8]
            "95 0f 8e 66 ac 05 47 21"	## Payload[0:16]
            "d6"			## Checksum.
        )),
        'response': bytes(0),
    },

    ##
    ## Challenge 3: Obtain the challenge answer.
    ##
    'UsbdSecXSM3GetResponseVerifyProtocolData3':
    {
        'packet': bytes.fromhex("c1 83 10 5c 03 01 16 00"),
        'response': bytes.fromhex((
            "49 4c 00 00 10"		## Header. 0x10 == 16
            "81 9e d2 80 9f e8 a9 59"	## Payload[0:8].
            "b5 88 bc a7 2d cb e1 f2"	## Payload[8:16].
            "19"			## Checksum.
        )),
    },
}



use_toypad = False
use_toypad = True
if use_toypad:
	device = lego_dimenions_toypad
else:
	device = genuine_controller



##
## Get static controller data.
##
## Parse the reply first, so we learn what the controller's static data 
## is.
console.parse_reply(device['UsbdSecXSM3GetIdentificationProtocolData']['response'])

## Tell our controller object what the controller's static data is.
if device['static_controller_data'] is not None:
    logger.debug(f"Known static controller data   : {device['static_controller_data'].hex(':')}")
    logger.debug(f"Computed static controller data: {console.static_controller_data.hex(':')}")
    assert console.static_controller_data == device['static_controller_data']
    logger.debug("Static controller data CONFIRMED.")
controller.static_controller_data = console.static_controller_data

computed_reply = controller.parse_control_transfer(device['UsbdSecXSM3GetIdentificationProtocolData']['packet'])
expected_reply = device['UsbdSecXSM3GetIdentificationProtocolData']['response']
logger.debug(f"computed_reply={computed_reply.hex(':')}")
logger.debug(f"expected_reply={expected_reply.hex(':')}")
## Compare results.
assert computed_reply == expected_reply



##
## Set challenge data. (1)
##
## Parse the packet, as it contains the console static and random data.
controller.parse_control_transfer(device['UsbdSecXSM3SetChallengeProtocolData']['packet'])

## Tell our console object what the console's static and random data is.
if device['static_console_data'] is not None:
    logger.debug(f"Known static console data   : {device['static_console_data'].hex(':')}")
    logger.debug(f"Computed static console data: {controller.static_console_data.hex(':')}")
    assert controller.static_console_data == device['static_console_data']
    logger.debug("Static console data CONFIRMED.")
console.static_console_data = controller.static_console_data

if device['random_console_data'] is not None:
    logger.debug(f"Known random console data   : {device['random_console_data'].hex(':')}")
    logger.debug(f"Computed random console data: {controller.random_console_data.hex(':')}")
    assert controller.random_console_data == device['random_console_data']
    logger.debug("Random console data CONFIRMED.")
console.random_console_data = controller.random_console_data

## We now know the static and random data of the console. Those two 
## ingredients are needed for (re)computing the challenge.
computed_packet = console.UsbdSecXSM3SetChallengeProtocolData()
expected_packet = device['UsbdSecXSM3SetChallengeProtocolData']['packet']
logger.debug(f"computed_packet={computed_packet.hex(':')}")
logger.debug(f"expected_packet={expected_packet.hex(':')}")
## Compare results.
assert computed_packet == expected_packet


##
## Get challenge response. (1)
##
## The controller reports his random data.
console.parse_reply(device['UsbdSecXSM3GetResponseVerifyProtocolData1']['response'])
controller.random_controller_data = console.random_controller_data

## We now know the random data of the controller. Use it to verify the 
## response.
computed_reply = controller.parse_control_transfer(device['UsbdSecXSM3GetResponseVerifyProtocolData1']['packet'])
expected_reply = device['UsbdSecXSM3GetResponseVerifyProtocolData1']['response']
logger.debug(f"computed_reply={computed_reply.hex(':')}")
logger.debug(f"expected_reply={expected_reply.hex(':')}")
## Compare results.
assert computed_reply == expected_reply



##
## Set challenge data. (2)
##
controller.parse_control_transfer(device['UsbdSecXSM3SetVerifyProtocolData2']['packet'])

##
## Get challenge response. (2)
##
computed_reply = controller.parse_control_transfer(device['UsbdSecXSM3GetResponseVerifyProtocolData2']['packet'])
expected_reply = device['UsbdSecXSM3GetResponseVerifyProtocolData2']['response']
logger.debug(f"computed_reply={computed_reply.hex(':')}")
logger.debug(f"expected_reply={expected_reply.hex(':')}")
## Compare results.
assert computed_reply == expected_reply



packet = None
try:
	packet = device['UsbdSecXSM3SetVerifyProtocolData3']['packet']
except KeyError as e:
	pass
if packet is not None:
	##
	## Set challenge data. (3)
	##
	controller.parse_control_transfer(device['UsbdSecXSM3SetVerifyProtocolData3']['packet'])

	##
	## Get challenge response. (3)
	##
	computed_reply = controller.parse_control_transfer(device['UsbdSecXSM3GetResponseVerifyProtocolData3']['packet'])
	expected_reply = device['UsbdSecXSM3GetResponseVerifyProtocolData3']['response']
	logger.debug(f"computed_reply={computed_reply.hex(':')}")
	logger.debug(f"expected_reply={expected_reply.hex(':')}")
	## Compare results.
	assert computed_reply == expected_reply
