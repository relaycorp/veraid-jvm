@file:JvmName("OrganisationCA")

package tech.relaycorp.vera.pki

import java.security.KeyPair
import java.time.ZonedDateTime
import tech.relaycorp.vera.utils.x509.Certificate

public fun KeyPair.selfIssueOrgCertificate(
    orgName: String,
    expiryDate: ZonedDateTime,
    startDate: ZonedDateTime = ZonedDateTime.now()
): ByteArray {
    val certificate = Certificate.issue(
        orgName,
        public,
        private,
        expiryDate,
        isCA = true,
        pathLenConstraint = 0,
        validityStartDate = startDate,
    )
    return certificate.serialize()
}
