# The Xbox 360 controller authentication process explained, with Python

## XSM3

XSM3 stands for *X*box *S*ecurity *M*ethod v3.

## Credits

The authentication process is known, I only read other people's 
repository to understand the authentication process, and to write my own 
implementations. Without said prior work, I would be dead in the water.

Repositories/links that helped me a lot:
* https://github.com/oct0xor/xbox_security_method_3
* https://github.com/InvoxiPlayGames/libxsm3
* https://github.com/GoobyCorp/Xbox-360-Crypto
* https://github.com/Santroller/Santroller

## Overview

The authentication process in short:
* The Xbox 360 requests identification data from the controller.
* The controller answers with (static) identification data.
* The Xbox 360 sends some static and some random data, encrypted.
* The controller decrpyts the message and stores static+random data.
* The Xbox 360 send a challenge to the controller.
* The controller answers.
* The Xbox 360 send another challenge to the controller.
* The controller answers.

## Keys

Two static keys are important in XSM3:
* ``e3 5b fb 1c cd ad 32 5b   f7 0e 07 fd 62 3d a7 c4`` (0x1D)
* ``8f 29 08 38 0b 5b fe 68   7c 26 46 2a 51 f2 bc 19`` (0x1E)

Those two keys are present in both the Xbox 360 as well as the controller.

Xbox 360: these 2 keys are in the keyvault. Controller: the key is 
inside the security chip.


Another set of keys is also important. For a controller, the keys are 
known as 0x23 and 0x24. In 
https://www.reddit.com/r/AskElectronics/comments/1isjhk2/comment/nh51vnt/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button, user sanjay900 wrote:

> If anybody ends up here: https://github.com/InvoxiPlayGames/libxsm3 
> and yes, dumping one of these exact controllers was how we found the 
> keys, but not how we reverse engineered the handshake, that was 
> already done by others.
> 
> We did this a while ago but i came across this post again when i was 
> looking into these chips for another reason.

For the LEGO Dimensions toypad, the keys are probably different, since 
we have been unsuccessful at replaying the authentication process.

## Details

### [UsbdSecXSM3GetIdentificationProtocolData] Xbox 360 asks for static device data

The Xbox 360 sends this IN packet to the device:
```
Setup Data:
c1 81 17 5b 03 01 1d 00

    bmRequestType: 0xc1
        1... .... = Direction: Device-to-host
        .10. .... = Type: Vendor (0x2)
        ...0 0001 = Recipient: Interface (0x01)
    bRequest: 129
    wValue: 0x5b17
    wIndex: 259 (0x0103)
    wLength: 29
```

https://oct0xor.github.io/2017/05/03/xsm3/ called this 
`UsbdSecXSM3GetIdentificationProtocolData`.

The device responds with an UNencrypted message containing the device's 
static data. What the static data represents, is mostly known.

Example responses of a wired Xbox 360 controller:
```
49 4b 00 00 17   4c 04 37 08 04 45 9c 29 02 03 20 00 00 80 02 5e 04 8e 02 03 00 01 01
```


The following links provide extra information about what the static data is:
* https://github.com/InvoxiPlayGames/libxsm3/blob/master/xsm3.c

So let's disect one packet:
```
49: Magic constant, packets start with this byte.
4b:
00:
00:
17: Length of the payload. 0x17 == 23 bytes

4c 04 37 08   04 45 9c 29   02 03 20 00	Serial
00 80					Unknown
02					Category node
5e 04					Vendor ID
8e 02					Product ID
03					Unknown
00					Unknown
01 01					Unknown

f5: Checksum over the payload.
```

Annotated details of several devices:
| Name                    | Header           | Serial (12 bytes)                     | ??      | Category node | Vendor ID | Product ID | ????          | Checksum | Source
|-------------------------|------------------|---------------------------------------|---------|---------------|-----------|------------|---------------|----------|-------
| Xbox 360 controller     | `49 4b 00 00 17` | `4c 04 37 08 04 45 9c 29 02 03 20 00` | `00 80` | `02`          | `5e 04`   | `8e 02`    | `03 00 01 01` | `f5`     | Our own wired controller
| Xbox 360 controller     | `49 4b 00 00 17` | `04 e1 11 54 15 ed 88 55 21 01 33 00` | `00 80` | `02`          | `5e 04`   | `8e 02`    | `03 00 01 01` | `c1`     | https://oct0xor.github.io/2017/05/03/xsm3/
| Xbox 360 controller     | `49 4b 00 00 17` | `84 3d 35 33 16 d6 33 28 23 03 20 00` | `00 80` | `82`          | `ad 1b`   | `01 fa`    | `03 00 01 01` | `28`     | https://brandonw.net/360bridge/Xbox360WiredController.xlsx
| LEGO Dimensions toypad  | `49 4b 00 00 17` | `74 ff 25 53 0e 11 85 25 38 03 20 00` | `00 80` | `82`          | `c6 24`   | `00 50`    | `03 00 01 01` | `ea`     | Our own toypad
| LEGO Dimensions toypad  | `49 4b 00 00 17` | `00 c9 18 25 05 11 85 25 38 03 20 00` | `00 80` | `82`          | `c6 24`   | `00 50`    | `03 00 01 01` | `e8`     | Our own toypad



### [UsbdSecXSM3SetChallengeProtocolData1] Xbox 360 challenges the device

The Xbox 360 sends this OUT packet:
```
Setup Data
    bmRequestType: 0x41
        0... .... = Direction: Host-to-device
        .10. .... = Type: Vendor (0x2)
        ...0 0001 = Recipient: Interface (0x01)
    bRequest: 130
    wValue: 0x0003
    wIndex: 259 (0x0103)
    wLength: 34
    Data Fragment: 094000001cb69ee4d8f725222cd8d6d252255c79bb264cfde55bbe5bb3c85a0ed7c9

41 82 03 00 03 01 22 00					## Setup data.
09 40 00 00 1c						## Header. 0x1c == 28
77 6f 34 2b 4c 16 6e c6   c4 04 22 0f f5 95 5b 28	## Payload[0:16]: Encrypted random data, generated by the Xbox 360
7d a6 f6 2a 3a 2b d8 32					## Payload[16:24]: Encrypted static console data, different for every Xbox 360.
ee 1d 69 1e						## Payload[24:28]: MAC
73							## Checksum.
```

The payload consists of two parts:
1. Encrypted data, 24 bytes.
2. MAC, 4 bytes.

The encrypted data is a single message containing two parts:
1. Random data.
2. Static data.

The static data differs from console to console. "Static" means static 
when on the same Xbox 360.

The encryption/decryption is done with two-key 3DES (K1=K3) and the 0x1D 
key:
```
e3 5b fb 1c cd ad 32 5b   f7 0e 07 fd 62 3d a7 c4   e3 5b fb 1c cd ad 32 5b
```
The IV is always all zero (i.e. 8 zero bytes).

The MAC is computed over the 24 encrypted bytes. The 0x1E key is used in 
the computation:
```
8f 29 08 38 0b 5b fe 68   7c 26 46 2a 51 f2 bc 19   8f 29 08 38 0b 5b fe 68
```

The device also has the 0x1D and 0x1E keys, so the device can decrypt 
the data, and therefore learns 2 important facts:
1. The Xbox 360's static data.
2. The Xbox 360's one-time data (random data).

The device start computing the response.



## UsbdSecXSM3GetStatus

The Xbox 360 queries the progress with this IN packet:
```
c1 86 00 00 03 01 02 00

Setup Data
    bmRequestType: 0xc1
        1... .... = Direction: Device-to-host
        .10. .... = Type: Vendor (0x2)
        ...0 0001 = Recipient: Interface (0x01)
    bRequest: 134
    wValue: 0x0000
    wIndex: 259 (0x0103)
    wLength: 2
```

The device may respond with:
1. `00 00`, meaning unknown, but seems to be an error condition.
2. `01 00`, meaning: I am not ready.
3. `02 00`, meaning: I am ready.



## UsbdSecXSM3GetResponseVerifyProtocolData

The Xbox 360 asks verification via this IN packet:
```
Setup Data
    bmRequestType: 0xc1
        1... .... = Direction: Device-to-host
        .10. .... = Type: Vendor (0x2)
        ...0 0001 = Recipient: Interface (0x01)
    bRequest: 131
    wValue: 0x5c28
    wIndex: 259 (0x0103)
    wLength: 46
```

The device must send some sort of verification that it has received the 
host's data correctly. Basically, the device just sends the host's 
random data and static data to prove correctly receiving the host's 
data. "Basically", because the device must prove much more at the same 
time.

The Xbox 360 and the device share another keypair. For wired 
controllers, these keys are known as 0x23 and 0x24. We reckon that 
"category node" 0x02 basically means: use keys 0x23 and 0x24.

The device must prove it has this keypair.

First, the devices computes two-key 3DES keys, derived from the 0x23 and 
0x24 keys:
1. Compute the SHA1 hash of the static data of the host. Note: Every 
   SHA1 hash is 20 bytes.
2. The first 16 bytes of the hash is encrypted with the 0x23 key and becomes 
   the first derived key.
3. The last 16 bytest of the hash is encrypted with the 0x24 key and becomes
   the second derived key.

By using these keys, the device proves it knowns the 0x23 and 0x24 key, 
and also proves that the device has received the static data correctly.

These two derived keys are used to derive yet another keypair: the 
device encrypts the host's random data this time. So if the device uses 
these "derived derived" keys, the device basically proves it has:
1. The 0x23 and 0x24 key.
2. The host's static data.
3. The host's random data.

The device hasn't send one-time data (random data) yet. The device uses 
this challenge to piggyback the device's random data. The device 
basically sends these bytes:
1. The device's random data.
2. The host's random data.

This message is encrypted with the first "derived derived" key. The MAC 
is computed using the second "derived derived" key. The ACR is computed 
using the MAC as key.
