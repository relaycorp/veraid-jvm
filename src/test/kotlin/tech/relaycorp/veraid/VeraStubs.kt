package tech.relaycorp.veraid

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import tech.relaycorp.veraid.pki.MemberCertificate
import tech.relaycorp.veraid.pki.OrgCertificate
import tech.relaycorp.veraid.pki.generateRSAKeyPair
import java.time.ZonedDateTime

const val ORG_NAME = "example.com"
val ORG_KEY_PAIR = generateRSAKeyPair()
internal val ORG_KEY_SPEC = OrganisationKeySpec(KeyAlgorithm.RSA_2048, "the-key-id")
internal val ORG_CERT =
    OrgCertificate.selfIssue(ORG_NAME, ORG_KEY_PAIR, ZonedDateTime.now().plusSeconds(60))

const val MEMBER_NAME = "alice"
val MEMBER_KEY_PAIR = generateRSAKeyPair()
internal val MEMBER_CERT = MemberCertificate.issue(
    MEMBER_NAME,
    MEMBER_KEY_PAIR.public,
    ORG_CERT,
    ORG_KEY_PAIR.private,
    ORG_CERT.expiryDate,
    ORG_CERT.startDate,
)

val SERVICE_OID = ASN1ObjectIdentifier("1.2.3.4.5")
