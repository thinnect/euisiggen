# Intergation Documentation

## Introduction
 This document provides knowhow how to load the license into the MCU to use beatstack.


 ## Requirements
  * Latest eusiggen (binaries available) : https://github.com/thinnect/euisiggen
  * Valid licence file

 ## Append licence file to signature file
```usersiggen --type license --sigfile signature.bin --licfile license.bin --out signature+license.bin```


## Install sig to MCU using thinnect platform configuration
   ```PROGRAM_SIGDATA=filename make ARCHITECTURE install-sig DEVICEID```