# VeraId library for the JVM

This is the JVM/Kotlin implementation of [VeraId](https://veraid.net), an offline authentication p**r**otoc**o**l powered by DNSSEC. This library implement**s** all the building blocks that signature producers and consumers need.

The usage and API documentation is available on [docs.relaycorp.tech](https://docs.relaycorp.tech/veraid-jvm/).

## Contributions

We love contributions! If you haven't contributed to a Relaycorp project before, please take a minute to [read our guidelines](https://github.com/relaycorp/.github/blob/master/CONTRIBUTING.md) first.

## Developer notes

### Naming conventions

We stick to the general naming conventions at Relaycorp, with the following exceptions:

- We distinguish between _serialisation_ (i.e., processing `ByteArray`s), _encoding_ (i.e., processing BouncyCastle ASN.1 objects) and _parsing_ (i.e., processing `String`s).
