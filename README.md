# The Xbox 360 controller authentication process explained, with Python

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

## Details

TODO.
