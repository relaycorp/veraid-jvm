package tech.relaycorp.veraid

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERSequence
import tech.relaycorp.veraid.utils.asn1.ASN1Exception
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
import tech.relaycorp.veraid.utils.asn1.toZonedDateTime

internal class SignatureMetadata(
    val service: ASN1ObjectIdentifier,
    val validityPeriod: DatePeriod,
) {
    init {
        if (validityPeriod.endInclusive < validityPeriod.start) {
            throw SignatureException(
                "End date should not be before start date " +
                    "(start=${validityPeriod.start}, end=${validityPeriod.endInclusive})",
            )
        }
    }

    fun encode() = ASN1Utils.makeSequence(listOf(service, validityPeriod.encode()), false)

    companion object {
        @Throws(SignatureException::class)
        fun decode(attributeValueTagged: ASN1Encodable): SignatureMetadata {
            val attributeValue = try {
                DERSequence.getInstance(attributeValueTagged)
            } catch (exc: IllegalArgumentException) {
                throw SignatureException("Encoding isn't a SEQUENCE", exc)
            }

            if (attributeValue.size() < 2) {
                throw SignatureException(
                    "Metadata SEQUENCE should have at least 2 items " +
                        "(got ${attributeValue.size()})",
                )
            }

            val serviceRaw = attributeValue.getObjectAt(0)
            val service = try {
                ASN1Utils.getOID(serviceRaw as ASN1TaggedObject)
            } catch (exc: ASN1Exception) {
                throw SignatureException("Service in metadata isn't an OID", exc)
            }

            val validityPeriodRaw = attributeValue.getObjectAt(1)
            val validityPeriod = try {
                DERSequence.getInstance(validityPeriodRaw as ASN1TaggedObject, false)
            } catch (exc: IllegalStateException) {
                throw SignatureException("Validity period in metadata isn't a SEQUENCE", exc)
            }

            if (validityPeriod.size() < 2) {
                throw SignatureException(
                    "Validity period in metadata should have at least 2 items " +
                        "(got ${validityPeriod.size()})",
                )
            }

            val startDate = try {
                val startDateRaw = validityPeriod.getObjectAt(0)
                (startDateRaw as ASN1TaggedObject).toZonedDateTime()
            } catch (exc: ASN1Exception) {
                throw SignatureException("Start date in metadata is invalid", exc)
            }

            val endDate = try {
                val endDateRaw = validityPeriod.getObjectAt(1)
                (endDateRaw as ASN1TaggedObject).toZonedDateTime()
            } catch (exc: ASN1Exception) {
                throw SignatureException("End date in metadata is invalid", exc)
            }

            return SignatureMetadata(service, startDate..endDate)
        }
    }
}
