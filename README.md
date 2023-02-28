# VeraId library for the JVM

This is the JVM/Kotlin implementation of [VeraId](https://veraid.net), an offline authentication protocol powered by DNSSEC. This library implements all the building blocks that signature producers and consumers need.

## Developer notes

### Naming conventions

We stick to the general naming conventions at Relaycorp, with the following exceptions:

- We distinguish between _serialisation_ (i.e., processing `ByteArray`s), _encoding_ (i.e., processing BouncyCastle ASN.1 objects) and _parsing_ (i.e., processing `String`s).
