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

Xbox 360: the key is in thee keyvault. Controller: the key is inside the 
security chip.


## Details

TODO.
