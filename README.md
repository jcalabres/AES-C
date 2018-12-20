# AES IMPLEMENTATION

This repository contains an AES Implementation wrote in C with MASK countermeasure.

## Build

Compile your source code with gcc compiler:

```c
gcc aes.c -o aes
```

## Usage

In order to use this AES implementation you should include the AES library to your project:

```C
 #include "aes.c"
 ```

 Once you have included the library, it's important to initialize a random seed to your project that
 will be used for AES randomness.

 ```C
 srand(time(0));
 ```

There's a list of the main functions for using the AES implementation.

* keyExpansion: Pass a key to do the AES key schedule in order to do all the keys for the rounds.
* cipher: Cipher the input.
* invCipher: Decipher the input.

## Example

There's an example about how to use this implementation:

```C
int main(){
  srand(time(0));

  uint8_t key[4][4]={
    {0x2b,0x7e,0x15,0x16},
    {0x28,0xae,0xd2,0xa6},
    {0xab,0xf7,0x15,0x88},
    {0x09,0xcf,0x4f,0x3c}};

  uint8_t in[4][4]={
    {0x32,0x43,0xf6,0xa8},
    {0x88,0x5a,0x30,0x8d},
    {0x31,0x31,0x98,0xa2},
    {0xe0,0x37,0x07,0x34}};

  uint8_t out1[4][4]={0};
	uint8_t out2[4][4]={0};

  uint8_t expanded[(nr+1)*4][4];

  keyExpansion(key,expanded,nk);
  cipher(in,out1,expanded);
	invCipher(out1,out2,expanded);
}
```

## Countermeasures

The MASK countermeasure applied attempts to protect implementations of cryptographic algorithms.

Protects against common power analysis type attacks:

* SPA: Side channel attack in which the attacker studies the power consumption of a cryptographic hardware devices.
* DPA: Differential power analysis attack is an exploit based on an analysis of the correlation between the electricity usage of a chip in a smart card and the encryption key it contains.

## Inspiration

A project inspired by:

* Announcing the ADVANCED ENCRYPTION STANDARD (AES).
* An Implementation of DES and AES, Secure against Some Attacks.

## Future work

* Conversion of the implementation to an AES White-Box crypto implementation.
* Rework functions to a best implemented ones.

## Authors

Implemented by Joan Calabrés.
