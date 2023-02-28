package tech.relaycorp.veraid.utils

import tech.relaycorp.veraid.utils.x509.Certificate
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZonedDateTime

internal fun issueStubCertificate(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    issuerCertificate: Certificate? = null,
    isCA: Boolean = false,
): Certificate {
    return Certificate.issue(
        "the subject for the stub cert",
        subjectPublicKey,
        issuerPrivateKey,
        ZonedDateTime.now().plusDays(1),
        isCA = isCA,
        issuerCertificate = issuerCertificate,
    )
}
