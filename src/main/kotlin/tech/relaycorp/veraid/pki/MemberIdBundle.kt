package tech.relaycorp.veraid.pki

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import tech.relaycorp.veraid.DatePeriod
import tech.relaycorp.veraid.dns.DnsException
import tech.relaycorp.veraid.dns.InvalidChainException
import tech.relaycorp.veraid.dns.VeraDnssecChain
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
import tech.relaycorp.veraid.utils.intersect
import tech.relaycorp.veraid.utils.x509.CertificateException

public class MemberIdBundle(
    internal val dnssecChain: VeraDnssecChain,
    internal val orgCertificate: OrgCertificate,
    internal val memberCertificate: MemberCertificate,
) {
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
    internal suspend fun verify(service: ASN1ObjectIdentifier, datePeriod: DatePeriod): Member {
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
                service,
                verificationPeriod,
            )
        } catch (exc: DnsException) {
            throw PkiException("DNS/DNSSEC resolution failed", exc)
        } catch (exc: InvalidChainException) {
            throw PkiException("Vera DNSSEC chain verification failed", exc)
        }

        return Member(orgCertificate.commonName, userName)
    }
}
