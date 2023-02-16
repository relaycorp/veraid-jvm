package tech.relaycorp.vera

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import tech.relaycorp.vera.pki.generateRSAKeyPair

const val ORG_NAME = "example.com"
val ORG_KEY_PAIR = generateRSAKeyPair()
internal val ORG_KEY_SPEC = OrganisationKeySpec(KeyAlgorithm.RSA_2048, "the-key-id")

const val MEMBER_NAME = "alice"
val MEMBER_KEY_PAIR = generateRSAKeyPair()

val SERVICE_OID = ASN1ObjectIdentifier("1.2.3.4.5")
