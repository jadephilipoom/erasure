# Host-side Secure Erasure Harness for Bao1x

This repository holds the host-side code for (provably) wiping memory. It was
written and tested for baochip-1x, although with the right device-side code it
could work with any other chip as well.

**Note: this code is under development and not yet in a stable state.**

## Overview

The basic methodology is to write a large amount of data to the chip, and then
have the chip use a proof-of-memory construct to show that it has all the data
present at the same time. The general idea is that this should make life
difficult for any unexpected or malicious code on the device to persist after
the operation, provided that the memory wiped is pretty close to the memory size
on the chip.

## How to use

1. Get device-side code that implements the correct protocol.
    a. For baochip-1x on dabao, you can find it
[here](https://github.com/jadephilipoom/xous-core/tree/erasure-dev). Run `cargo
xtask bao1x-erasure-dabao` and copy the erasure.uf2 file onto the chip, then
press PROG to boot. 
2. Run the host-side code, pointing it at the serial port that communicates with
   the chip. For example:

```
cargo run -- /dev/ttyACM0 test.txt ../xous-core/target/riscv32imac-unknown-none-elf/release/erasure
``` 

## Protocol

The expected interaction between host and device is:

1. Host sends:
   1a. 4 bytes indicating requested ack frequency in bytes.
   1b. 4 bytes indicating the size of the device-side code.
2. Device sends 4 bytes indicating requested total byte length.
3. Repeat until total byte length is reached:
   3a. Host sends <ack frequency> bytes, or remaining bytes if less.
   3b. Device sends 4 bytes, encoding the total bytes received so far.
4. Host sends the key and seed blocks.
5. Device sends the recovered key.

Optionally, the device can then decrypt the ciphertext using the key.

## Cryptography

The current approach is modelled on the paper [Secure Erasure and Code Update
for Legacy Sensors](https://www.ghassankarame.com/secure_code.pdf), where it is
called SUANT. In SUANT, the host pads some plaintext data (the desired
post-update code) until it is the size of the memory on the device, encrypts it
under a random ephemeral key, and writes the ciphertext to the device. Then the
host generates a random seed and uses it to generate a sequence of shift and xor
operations covering the entire ciphertext. The resulting block is then XORed
with the encryption key and sent to the device, along with the seed. The device,
if it has all ciphertext present, can use the seed to compute the same sequence
of operations on the ciphertext and then use XOR to recover the encryption key.
It sends this to the host to prove that it had all the ciphertext in memory
simultaneously. It can then decrypt the ciphertext to get its new state.

There are a couple of divergences from SUANT in the current implementation, most
notably that the paper assumes that the device-side code is in read-only memory
and does not need to be covered by the erasure check. We don't make the same
assumption.

Instead, we analyze the device-side binary to determine a certain amount of data
to *not* overwrite, and then incorporate the plaintext code along with the
ciphertext in the shift-xor sequence. This is not as strong of a guarantee as
including ciphertext, because code is much more compressible and in theory an
attacker could compress the code and keep a malicious program in the freed
space. Because we run shift-xor over the code, such an attacker would then need
to decompress the code during key recovery. Keeping a close eye on key recovery
timings and minimizing the device-side code size helps mitigate this risk.

Although the first pass at this implementation closely follows the paper, the
approach in this repo might change longer-term. It's not clear that update is
actually needed in the target context, for example, so it might make sense to
just drop the encryption entirely and write random numbers. It also might make
sense to use something with hardware support, like a hash function, instead of
the shift-xor approach, in order to minimize device-side code size.
