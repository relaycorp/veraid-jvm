package tech.relaycorp.veraid

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import tech.relaycorp.veraid.dns.VeraDnssecChain
import tech.relaycorp.veraid.pki.MemberIdBundle
import tech.relaycorp.veraid.pki.OrgCertificate
import tech.relaycorp.veraid.utils.cms.SignedData
import java.security.PrivateKey
import java.time.ZonedDateTime

public class SignatureBundle private constructor(
    internal val chain: VeraDnssecChain,
    internal val orgCertificate: OrgCertificate,
    internal val signedData: SignedData,
    internal val metadata: SignatureMetadata,
) {
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
            val signedData = SignedData.sign(
                plaintext,
                signingKey,
                memberIdBundle.memberCertificate,
                setOf(memberIdBundle.memberCertificate, memberIdBundle.orgCertificate),
                encapsulatePlaintext = false,
            )
            return SignatureBundle(
                memberIdBundle.dnssecChain,
                memberIdBundle.orgCertificate,
                signedData,
                metadata,
            )
        }
    }
}
