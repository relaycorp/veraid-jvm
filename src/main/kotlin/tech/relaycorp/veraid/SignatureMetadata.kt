package tech.relaycorp.veraid

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute
import tech.relaycorp.veraid.utils.asn1.ASN1Utils

internal class SignatureMetadata(
    private val service: ASN1ObjectIdentifier,
    private val validityPeriod: DatePeriod,
) {
    fun encode() = Attribute(
        VeraOids.SIGNATURE_METADATA_ATTR,
        DERSet(ASN1Utils.makeSequence(listOf(service, validityPeriod.encode()), false)),
    )
}
