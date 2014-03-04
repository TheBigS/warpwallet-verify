WarpWallet Verification
=======================

Java WarpWallet(https://keybase.io/warp) verification project. I put this together to independently verify that the calculations being done by WarpWallet matched both SCrypt and PBKDF2 algorithms.

Compiling
=========

`gradle build`

Usage
=====
`java -jar warpwallet-verify.jar <password> [salt]`
Example: `java -jar warpwallet-verify.jar test test@test.com`

Output:
```
Password: test
Salt: test@test.com
SCrypt Result: 5405ac36f5e9b59914d2b53311984c9ea6330faa384f7078c8be7bbc2f3896d8
PBKDF2 Result: 0b342e09cdb609cd4bc39a9815df5bf870fab98cd4bd94418d977f35691002b4
Private Key  : 5f31823f385fbc545f112fab04471766d6c9b626ecf2e439452904894628946c
Private Key Encoded : 5JYDAkj6icvkXuKSnFAveGZzGyAteMuufvUhMkje8Z1dA8cshjS
```

License
=======

Apache 2.0

Attributions
=============
This project utilizes the following libraries under the following licenses:
+ Apache Commons Collections (Apache 2.0)
+ github.com/wg/scrypt (Apache 2.0)
+ JUnit (BSD)
