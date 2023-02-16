package tech.relaycorp.veraid.utils.x509

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERSequence

/**
 * X.509 BasicConstraints extension.
 *
 * BouncyCastle's BasicConstraints class no longer supports setting both attributes on the
 * extension, so we have to do it ourselves.
 */
internal class BasicConstraintsExtension(
    private val cA: Boolean,
    private val pathLenConstraint: Int
) : ASN1Encodable {
    init {
        if (pathLenConstraint < 0 || 2 < pathLenConstraint) {
            throw CertificateException(
                "pathLenConstraint should be between 0 and 2 (got $pathLenConstraint)"
            )
        }
        if (pathLenConstraint != 0 && !cA) {
            throw CertificateException(
                "Subject should be a CA if pathLenConstraint=$pathLenConstraint"
            )
        }
    }

    override fun toASN1Primitive(): ASN1Primitive {
        val sequence = ASN1EncodableVector(2)
        sequence.add(ASN1Boolean.getInstance(cA))
        sequence.add(ASN1Integer(pathLenConstraint.toLong()))
        return DERSequence(sequence)
    }
}
