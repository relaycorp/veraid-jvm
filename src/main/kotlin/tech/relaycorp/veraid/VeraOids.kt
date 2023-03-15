package tech.relaycorp.veraid

import org.bouncycastle.asn1.ASN1ObjectIdentifier

internal object VeraOids {
    // Alias: iso.org.dod.internet.private.enterprise.relaycorp
    private val RELAYCORP = ASN1ObjectIdentifier("1.3.6.1.4.1.58708")

    private val VERA = RELAYCORP.branch("1")

    val SIGNATURE_METADATA_ATTR: ASN1ObjectIdentifier = VERA.branch("0")
}
