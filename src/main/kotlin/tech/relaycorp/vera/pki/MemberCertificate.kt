package tech.relaycorp.vera.pki

import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZonedDateTime
import org.bouncycastle.cert.X509CertificateHolder
import tech.relaycorp.vera.utils.x509.Certificate

public class MemberCertificate internal constructor(certificateHolder: X509CertificateHolder) :
    Certificate(certificateHolder) {
    public companion object {
        private val FORBIDDEN_USER_NAME_CHARS_REGEX = "[@\t\r\n]".toRegex()
        private const val BOT_USER_NAME = "@"

        public fun issue(
            userName: String?,
            memberPublicKey: PublicKey,
            orgCertificate: OrgCertificate,
            orgPrivateKey: PrivateKey,
            expiryDate: ZonedDateTime,
            startDate: ZonedDateTime = ZonedDateTime.now()
        ): MemberCertificate {
            if (userName != null) {
                validateUserName(userName)
            }
            return MemberCertificate(
                issue(
                    userName ?: BOT_USER_NAME,
                    memberPublicKey,
                    orgPrivateKey,
                    expiryDate,
                    orgCertificate,
                    validityStartDate = startDate,
                ).certificateHolder
            )
        }

        private fun validateUserName(userName: String) {
            if (FORBIDDEN_USER_NAME_CHARS_REGEX.containsMatchIn(userName)) {
                throw PKIException(
                    "User name should not contain at signs or whitespace other than simple spaces"
                )
            }
        }
    }
}
