# Module veraid

This is the JVM/Kotlin implementation of [VeraId](https://veraid.net), an offline authentication protocol powered by DNSSEC. This library implements all the building blocks that signature producers and consumers need.

The latest version can be found on [Maven Central](https://central.sonatype.com/search?q=veraid&namespace=tech.relaycorp), and the source code on [GitHub](https://github.com/relaycorp/veraid-jvm).

## Signature production

To produce a signature for a given plaintext, you need a _Member Id Bundle_ (produced by a VeraId organisation; e.g., via [VeraId Authority](https://github.com/relaycorp/veraid-authority)) and the Member's private key.

For example, if you wanted to produce signatures valid for up to 30 days for a service identified by the [OID](https://en.wikipedia.org/wiki/Object_identifier) `1.2.3.4.5`, you could implement the following function and call it in your code:

```kotlin
import java.security.PrivateKey
import java.time.ZonedDateTime
import kotlin.time.Duration.Companion.days
import kotlin.time.toJavaDuration
import tech.relaycorp.veraid.pki.MemberIdBundle
import tech.relaycorp.veraid.SignatureBundle

val TTL = 30.days
val SERVICE_OID = "1.2.3.4.5"

fun produceSignature(
    plaintext: ByteArray,
    memberIdBundleSerialised: ByteArray,
    memberSigningKey: PrivateKey,
): ByteArray {
    val memberIdBundle = MemberIdBundle.deserialise(memberIdBundleSerialised)
    val expiryDate = ZonedDateTime.now().plus(TTL.toJavaDuration())
    val signatureBundle = SignatureBundle.generate(
        plaintext,
        SERVICE_OID,
        memberIdBundle,
        memberSigningKey,
        expiryDate,
    )
    return signatureBundle.serialise()
}
```

The Signature Bundle contains the Member Id Bundle and the actual signature, but it does not include the `plaintext`.

Note that for signatures to actually be valid for up to 30 days, the TTL override in the VeraId TXT record should allow 30 days or more.

## Signature verification

To verify a VeraId signature, you simply need the Signature Bundle and the plaintext to be verified. For extra security, this library also requires you to confirm the service where you intend to use the plaintext.

If VeraId's maximum TTL of 90 days or the TTL specified by the signature producer may be too large for your application, you may also want to restrict the validity period of signatures.

For example, if you only want to accept signatures valid for the past 30 days in a service identified by `1.2.3.4.5`, you could use the following function:

```kotlin
import java.security.PrivateKey
import java.time.ZonedDateTime
import kotlin.time.Duration.Companion.days
import kotlin.time.toJavaDuration
import tech.relaycorp.veraid.pki.MemberIdBundle
import tech.relaycorp.veraid.SignatureBundle
import tech.relaycorp.veraid.SignatureException

val TTL = 30.days
val SERVICE_OID = "1.2.3.4.5"

suspend fun verifySignature(
    plaintext: ByteArray,
    signatureBundleSerialised: ByteArray,
): String {
    val signatureBundle = SignatureBundle.deserialise(signatureBundleSerialised)
    
    val now = ZonedDateTime.now()
    val verificationPeriod = now.minus(TTL.toJavaDuration())..now
    val (_, member) = try {
        signatureBundle.verify(plaintext, SERVICE_OID, verificationPeriod)
    } catch (exc: SignatureException) {
        throw Exception("Invalid signature bundle", exc)
    }
    
    return if (member.userName == null) member.orgName else "${member.userName}@${member.orgName}"
}
```

`verifySignature()` will return the id of the member that signed the plaintext, which looks like `user@example.com` if the member is a user or simply `example.com` if the member is a bot (acting on behalf of the organisation `example.com`).

# Package tech.relaycorp.veraid

Root package for the VeraId library.

# Package tech.relaycorp.veraid.dns

DNS- and DNSSEC-related functionality.

# Package tech.relaycorp.veraid.pki

VeraId's public key infrastructure (e.g., X.509 certificate processing).
