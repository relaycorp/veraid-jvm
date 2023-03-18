package tech.relaycorp.veraid.pki

import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.cert.X509CertificateHolder
import tech.relaycorp.veraid.utils.x509.Certificate
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZonedDateTime

/**
 * VeraId Member Certificate.
 *
 * @property userName The user's name if the member is a user, or `null` if it's a bot.
 */
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

        /**
         * Issue a new member certificate.
         *
         * @param userName The user's name if the member is a user, or `null` if it's a bot.
         * @param memberPublicKey The member's public key.
         * @param orgCertificate The organisation's certificate.
         * @param orgPrivateKey The organisation's private key.
         * @param expiryDate The certificate's expiry date.
         * @param startDate The certificate's start date.
         */
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

        internal fun decode(encoding: ASN1TaggedObject): MemberCertificate =
            MemberCertificate(Certificate.decode(encoding).certificateHolder)

        internal fun validateUserName(userName: String) {
            if (FORBIDDEN_USER_NAME_CHARS_REGEX.containsMatchIn(userName)) {
                throw PkiException(
                    "User name should not contain at signs or whitespace other than simple spaces",
                )
            }
        }
    }
}
