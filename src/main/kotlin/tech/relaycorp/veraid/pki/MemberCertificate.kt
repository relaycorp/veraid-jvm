package tech.relaycorp.veraid.pki

import org.bouncycastle.cert.X509CertificateHolder
import tech.relaycorp.veraid.utils.x509.Certificate
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZonedDateTime

public class MemberCertificate internal constructor(certificateHolder: X509CertificateHolder) :
    Certificate(certificateHolder) {
    internal val userName: String? by lazy {
        if (commonName == BOT_NAME) {
            null
        } else {
            commonName
        }
    }

    public companion object {
        private val FORBIDDEN_USER_NAME_CHARS_REGEX = "[@\t\r\n]".toRegex()
        private const val BOT_NAME = "@"

        public fun issue(
            userName: String?,
            memberPublicKey: PublicKey,
            orgCertificate: OrgCertificate,
            orgPrivateKey: PrivateKey,
            expiryDate: ZonedDateTime,
            startDate: ZonedDateTime = ZonedDateTime.now(),
        ): MemberCertificate {
            if (userName != null) {
                validateUserName(userName)
            }
            return MemberCertificate(
                issue(
                    userName ?: BOT_NAME,
                    memberPublicKey,
                    orgPrivateKey,
                    expiryDate,
                    orgCertificate,
                    validityStartDate = startDate,
                ).certificateHolder,
            )
        }

        internal fun validateUserName(userName: String) {
            if (FORBIDDEN_USER_NAME_CHARS_REGEX.containsMatchIn(userName)) {
                throw PkiException(
                    "User name should not contain at signs or whitespace other than simple spaces",
                )
            }
        }
    }
}
