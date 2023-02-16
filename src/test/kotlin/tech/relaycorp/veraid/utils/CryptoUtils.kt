package tech.relaycorp.veraid.utils

import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZonedDateTime
import tech.relaycorp.veraid.utils.x509.Certificate

fun sha256(input: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(input)
}

internal fun issueStubCertificate(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    issuerCertificate: Certificate? = null,
    isCA: Boolean = false
): Certificate {
    return Certificate.issue(
        "the subject for the stub cert",
        subjectPublicKey,
        issuerPrivateKey,
        ZonedDateTime.now().plusDays(1),
        isCA = isCA,
        issuerCertificate = issuerCertificate
    )
}
