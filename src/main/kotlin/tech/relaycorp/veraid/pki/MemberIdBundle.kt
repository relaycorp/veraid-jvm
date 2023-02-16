package tech.relaycorp.veraid.pki

import org.bouncycastle.asn1.ASN1Integer
import tech.relaycorp.veraid.dns.VeraDnssecChain
import tech.relaycorp.veraid.utils.asn1.ASN1Utils

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
