package tech.relaycorp.veraid.pki

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import tech.relaycorp.veraid.DatePeriod
import tech.relaycorp.veraid.Member
import tech.relaycorp.veraid.dns.DnsException
import tech.relaycorp.veraid.dns.DnssecChain
import tech.relaycorp.veraid.dns.InvalidChainException
import tech.relaycorp.veraid.utils.asn1.ASN1Exception
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
import tech.relaycorp.veraid.utils.intersect
import tech.relaycorp.veraid.utils.x509.CertificateException
import java.security.PublicKey

/**
 * Member Id bundle.
 *
 * It contains the DNSSEC chain for the VeraId TXT RRSet (e.g., `_veraid.example.com./TXT`), the
 * organisation certificate and the member certificate.
 */
public class MemberIdBundle(
    internal val dnssecChain: DnssecChain,
    internal val orgCertificate: OrgCertificate,
    internal val memberCertificate: MemberCertificate,
) {
    /**
     * Member public key.
     */
    public val memberPublicKey: PublicKey
        get() = memberCertificate.subjectPublicKey

    /**
     * Serialise the bundle.
     */
    public fun serialise(): ByteArray = ASN1Utils.serializeSequence(
        listOf(
            ASN1Integer(0),
            dnssecChain.encode(),
            orgCertificate.encode(),
            memberCertificate.encode(),
        ),
        false,
    )

    @Throws(PkiException::class)
    public suspend fun verify(serviceOid: String, datePeriod: DatePeriod): Member {
        try {
            memberCertificate.getCertificationPath(emptyList(), listOf(orgCertificate))
        } catch (exc: CertificateException) {
            throw PkiException("Member certificate was not issued by organisation", exc)
        }

        val certsPeriod =
            memberCertificate.validityPeriod.intersect(orgCertificate.validityPeriod)!!
        val verificationPeriod = datePeriod.intersect(certsPeriod)
            ?: throw PkiException(
                "Validity period of certificate chain does not overlap with required period",
            )

        val userName = memberCertificate.userName
        if (userName != null) {
            MemberCertificate.validateUserName(userName)
        }

        if (orgCertificate.commonName != dnssecChain.orgName) {
            throw PkiException("Organisation certificate does not correspond to DNSSEC chain")
        }

        try {
            dnssecChain.verify(
                orgCertificate.subjectPublicKey.orgKeySpec,
                ASN1ObjectIdentifier(serviceOid),
                verificationPeriod,
            )
        } catch (exc: DnsException) {
            throw PkiException("DNS/DNSSEC resolution failed", exc)
        } catch (exc: InvalidChainException) {
            throw PkiException("VeraId DNSSEC chain verification failed", exc)
        }

        return Member(orgCertificate.commonName, userName)
    }

    public companion object {
        /**
         * Deserialise a bundle.
         */
        @Throws(PkiException::class)
        @JvmStatic
        public fun deserialise(serialisation: ByteArray): MemberIdBundle {
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialisation)
            } catch (exc: ASN1Exception) {
                throw PkiException("Member Id Bundle should be a SEQUENCE", exc)
            }

            if (sequence.size < 4) {
                throw PkiException("Member Id Bundle should have at least 4 items")
            }

            val orgCertificate = try {
                OrgCertificate.decode(sequence[2])
            } catch (exc: CertificateException) {
                throw PkiException("Organisation certificate is malformed", exc)
            }

            val dnssecChain = try {
                DnssecChain.decode(orgCertificate.commonName, sequence[1])
            } catch (exc: InvalidChainException) {
                throw PkiException("DNSSEC chain is malformed", exc)
            }

            val memberCertificate = try {
                MemberCertificate.decode(sequence[3])
            } catch (exc: CertificateException) {
                throw PkiException("Member certificate is malformed", exc)
            }

            return MemberIdBundle(dnssecChain, orgCertificate, memberCertificate)
        }
    }
}
