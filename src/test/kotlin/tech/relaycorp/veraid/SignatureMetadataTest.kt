package tech.relaycorp.veraid

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.beInstanceOf
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DERSequence
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
import java.time.ZonedDateTime

class SignatureMetadataTest {
    @Nested
    inner class Encode {
        private val now = ZonedDateTime.now()
        private val validityPeriod = now..now.plusSeconds(5)
        private val metadata = SignatureMetadata(SERVICE_OID, validityPeriod)

        @Test
        fun `Attribute should use correct OID`() {
            val attribute = metadata.encode()

            attribute.attrType shouldBe VeraOids.SIGNATURE_METADATA_ATTR
        }

        @Test
        fun `Attribute should have a single value`() {
            val attribute = metadata.encode()

            attribute.attrValues shouldHaveSize 1
        }

        @Test
        fun `Attribute value should be be implicitly-tagged SEQUENCE`() {
            val attribute = metadata.encode()

            val attributeValue = attribute.attrValues.single()
            attributeValue should beInstanceOf<DERSequence>()
            attributeValue as DERSequence
            shouldNotThrowAny {
                ASN1ObjectIdentifier.getInstance(
                    attributeValue.getObjectAt(0) as ASN1TaggedObject,
                    false,
                )
                DERSequence.getInstance(
                    attributeValue.getObjectAt(1) as ASN1TaggedObject,
                    false,
                )
            }
        }

        @Test
        fun `Service OID should be output`() {
            val attribute = metadata.encode()

            val attributeSequence = attribute.attributeValues.single() as ASN1Sequence
            val serviceOid = ASN1Utils.getOID(attributeSequence.getObjectAt(0) as ASN1TaggedObject)
            serviceOid shouldBe SERVICE_OID
        }

        @Test
        fun `Validity period should be output as SEQUENCE`() {
            val attribute = metadata.encode()

            val attributeSequence = attribute.attributeValues.single() as ASN1Sequence
            val validityPeriod = attributeSequence.getObjectAt(1)
            shouldNotThrowAny {
                ASN1Sequence.getInstance(validityPeriod as ASN1TaggedObject, false)
            }
        }

        @Test
        fun `Start date should be included in validity period`() {
            val attribute = metadata.encode()

            val attributeSequence = attribute.attributeValues.single() as ASN1Sequence
            val validityPeriodSequence = ASN1Sequence.getInstance(
                attributeSequence.getObjectAt(1) as ASN1TaggedObject,
                false,
            )
            val startDate = DERGeneralizedTime.getInstance(
                validityPeriodSequence.getObjectAt(0) as ASN1TaggedObject?,
                false,
            )
            startDate shouldBe ASN1Utils.derEncodeUTCDate(validityPeriod.start)
        }

        @Test
        fun `End date should be included in validity period`() {
            val attribute = metadata.encode()

            val attributeSequence = attribute.attributeValues.single() as ASN1Sequence
            val validityPeriodSequence = ASN1Sequence.getInstance(
                attributeSequence.getObjectAt(1) as ASN1TaggedObject,
                false,
            )
            val endDate = DERGeneralizedTime.getInstance(
                validityPeriodSequence.getObjectAt(1) as ASN1TaggedObject?,
                false,
            )
            endDate shouldBe ASN1Utils.derEncodeUTCDate(validityPeriod.endInclusive)
        }
    }
}
