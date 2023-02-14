package tech.relaycorp.vera.dns

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import tech.relaycorp.vera.KeyAlgorithm
import tech.relaycorp.vera.OrganisationKeySpec

const val ORGANISATION_NAME = "example.com"
val SERVICE_OID = ASN1ObjectIdentifier("1.2.3.4.5")
internal val ORG_KEY_SPEC = OrganisationKeySpec(KeyAlgorithm.RSA_2048, "the-key-id")
