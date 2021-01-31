# Covert

Covert is a deniable encryption software.

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=crashdump_covert&metric=alert_status)](https://sonarcloud.io/dashboard?id=crashdump_covert)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=crashdump_covert&metric=bugs)](https://sonarcloud.io/dashboard?id=crashdump_covert)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=crashdump_covert&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=crashdump_covert)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=crashdump_covert&metric=code_smells)](https://sonarcloud.io/dashboard?id=crashdump_covert)

## Disclaimer

Covert is an early stage **research prototype** and comes with absolutely **no warranty**.

## Description

"In cryptography and steganography, plausibly deniable encryption describes encryption techniques where
the existence of an encrypted file or message is deniable in the sense that an adversary cannot prove
that the plaintext data exists." – [Wikipedia](https://en.wikipedia.org/wiki/Deniable_encryption)

## Scenario

Deniable encryption allows the sender of an encrypted message to deny sending that message. This requires a trusted
third party. A possible scenario looks like this:

Bob needs to travel to a country with a legislation that requires individuals to surrender cryptographic keys to law
enforcement. That being the case, Bob wants to keep his private data out of their eyes, to protect his privacy. He
creates two keys, one intended to be kept secret, the other intended to be sacrificed.

Bob constructs an innocuous message M1 (intended to be revealed to the secret police in case of discovery) and another
one, containing the personal data M2 he does not want anyone to know about.

He constructs a cipher-text C out of both messages, M1 and M2, stores it on his device.

Bob travels to the country, passes the border control and later uses his key to decrypt M2 (and possibly M1, in order
to read the decoy message, too).

The secret police arrest Bob and finds the encrypted blob on his device, becomes suspicious and forces Bob to decrypt
the message.

Bob uses the sacrificial key and reveals the innocuous message M1 to the secret police. Since it is impossible for them
to know for sure if there are other messages contained in C, they might assume that there are no other messages.

## Goals

Bear in mind this project was created with the _requirements_ below in mind, it may not suit your use case.

### Requirements

* Use known and proven cryptographic algorithms (AES-256, PBKDF2) and libraries.
* The system must be mathematically indecipherable without the key.
* The mechanism should not require secrecy, and it should not be a problem if it falls into enemy hands.
* An adversary cannot prove concealed content exists without observing the program's execution during encryption.
* Portable, without any system dependencies (statically linked binaries).
* Does not require kernel or userspace filesystems.

## Algorithms

Covert uses *scrypt* to hash the passphrases and *AES256-GCM* to encrypt the partitions.

## Documentation

All the documentation lives in the `docs` folder.

### How to
- [Cli usage](docs/usage.md)
- [Library](docs/library.md)

### Technical details
- [Approach](docs/approach.md)

## License

GNU Lesser General Public version 3. See [LICENSE.md](LICENSE.md)