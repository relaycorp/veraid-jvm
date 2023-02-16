package tech.relaycorp.veraid.pki

import java.security.KeyPair
import java.time.ZonedDateTime
import org.bouncycastle.cert.X509CertificateHolder
import tech.relaycorp.veraid.utils.x509.Certificate

public class OrgCertificate internal constructor(certificateHolder: X509CertificateHolder) :
    Certificate(certificateHolder) {
    public companion object {
        public fun selfIssue(
            orgName: String,
            orgKeyPair: KeyPair,
            expiryDate: ZonedDateTime,
            startDate: ZonedDateTime = ZonedDateTime.now()
        ): OrgCertificate = OrgCertificate(
            issue(
                orgName,
                orgKeyPair.public,
                orgKeyPair.private,
                expiryDate,
                isCA = true,
                pathLenConstraint = 0,
                validityStartDate = startDate,
            ).certificateHolder
        )
    }
}
