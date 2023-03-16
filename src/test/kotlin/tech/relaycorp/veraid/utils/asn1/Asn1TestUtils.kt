package tech.relaycorp.veraid.utils.asn1

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLTaggedObject

fun parseDer(derSerialization: ByteArray): ASN1Primitive {
    val asn1Stream = ASN1InputStream(derSerialization)
    return asn1Stream.readObject()
}

fun ASN1Encodable.toDlTaggedObject(explicitlyTagged: Boolean) =
    DLTaggedObject(explicitlyTagged, 1, this)
