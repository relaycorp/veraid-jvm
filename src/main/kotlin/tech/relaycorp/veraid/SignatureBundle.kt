package tech.relaycorp.veraid

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute
import tech.relaycorp.veraid.dns.VeraDnssecChain
import tech.relaycorp.veraid.pki.MemberIdBundle
import tech.relaycorp.veraid.pki.OrgCertificate
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
import tech.relaycorp.veraid.utils.cms.SignedData
import java.security.PrivateKey
import java.time.ZonedDateTime

public class SignatureBundle internal constructor(
    internal val chain: VeraDnssecChain,
    internal val orgCertificate: OrgCertificate,
    internal val signedData: SignedData,
) {
    public fun serialise(): ByteArray = ASN1Utils.serializeSequence(
        listOf(
            ASN1Integer(0),
            chain.encode(),
            orgCertificate.encode(),
            signedData.encode(),
        ),
        false,
    )

    public companion object {
        public fun generate(
            plaintext: ByteArray,
            serviceOid: String,
            memberIdBundle: MemberIdBundle,
            signingKey: PrivateKey,
            expiryDate: ZonedDateTime,
            startDate: ZonedDateTime = ZonedDateTime.now(),
        ): SignatureBundle {
            val metadata = SignatureMetadata(
                ASN1ObjectIdentifier(serviceOid),
                startDate..expiryDate,
            )
            val metadataAttribute = Attribute(
                VeraOids.SIGNATURE_METADATA_ATTR,
                DERSet(metadata.encode()),
            )
            val signedData = SignedData.sign(
                plaintext,
                signingKey,
                memberIdBundle.memberCertificate,
                setOf(memberIdBundle.memberCertificate, memberIdBundle.orgCertificate),
                encapsulatePlaintext = false,
                extraSignedAttrs = listOf(metadataAttribute),
            )
            return SignatureBundle(
                memberIdBundle.dnssecChain,
                memberIdBundle.orgCertificate,
                signedData,
            )
        }
    }
}
