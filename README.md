# vera-jvm

VeraId library for the JVM

## Developer notes

### Naming conventions

We stick to the general naming conventions at Relaycorp, with the following exceptions:

- We distinguish between _serialisation_ and _encoding_: The former applies when processing `ByteArray`s, and the latter when processing ASN.1 (DER) instances from Bouncy Castle.
