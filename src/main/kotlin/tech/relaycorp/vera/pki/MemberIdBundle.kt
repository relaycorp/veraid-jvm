package tech.relaycorp.vera.pki

import org.bouncycastle.asn1.ASN1Integer
import tech.relaycorp.vera.dns.VeraDnssecChain
import tech.relaycorp.vera.utils.asn1.ASN1Utils

public class MemberIdBundle(
    private val dnssecChain: VeraDnssecChain,
    private val orgCertificate: OrgCertificate,
    private val memberCertificate: MemberCertificate
) {
    public fun serialise(): ByteArray = ASN1Utils.serializeSequence(
        listOf(
            ASN1Integer(0),
            dnssecChain.encode(),
            orgCertificate.encode(),
            memberCertificate.encode()
        ),
        false,
    )
}
