package tech.relaycorp.veraid.pki

import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.cert.X509CertificateHolder
import tech.relaycorp.veraid.utils.x509.Certificate
import tech.relaycorp.veraid.utils.x509.CertificateException
import java.security.KeyPair
import java.time.ZonedDateTime

/**
 * VeraId organisation certificate.
 */
public class OrgCertificate internal constructor(certificateHolder: X509CertificateHolder) :
    Certificate(certificateHolder) {
    public companion object {
        /**
         * Issue a new organisation certificate.
         *
         * @param orgName The organisation name.
         * @param orgKeyPair The organisation's key pair.
         * @param expiryDate The certificate's expiry date.
         * @param startDate The certificate's start date.
         */
        public fun selfIssue(
            orgName: String,
            orgKeyPair: KeyPair,
            expiryDate: ZonedDateTime,
            startDate: ZonedDateTime = ZonedDateTime.now(),
        ): OrgCertificate = OrgCertificate(
            issue(
                orgName.trimEnd('.'),
                orgKeyPair.public,
                orgKeyPair.private,
                expiryDate,
                isCA = true,
                pathLenConstraint = 0,
                validityStartDate = startDate,
            ).certificateHolder,
        )

        @Throws(CertificateException::class)
        internal fun decode(encoding: ASN1TaggedObject): OrgCertificate =
            OrgCertificate(Certificate.decode(encoding).certificateHolder)
    }
}
