package tech.relaycorp.veraid

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.beInstanceOf
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSequence
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.utils.asn1.ASN1Exception
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
import tech.relaycorp.veraid.utils.asn1.toGeneralizedTime
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit

class SignatureMetadataTest {
    private val now =
        ZonedDateTime.now().withZoneSameInstant(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS)
    private val validityPeriod = now..now.plusSeconds(5)
    private val metadata = SignatureMetadata(SERVICE_OID, validityPeriod)

    @Nested
    inner class Constructor {
        @Test
        fun `End date should not be before start date`() {
            val invalidPeriod = validityPeriod.endInclusive..validityPeriod.start

            val exception = shouldThrow<SignatureException> {
                SignatureMetadata(SERVICE_OID, invalidPeriod)
            }

            exception.message shouldBe "End date should not be before start date " +
                "(start=${validityPeriod.endInclusive}, end=${validityPeriod.start})"
        }
    }

    @Nested
    inner class Encode {
        @Test
        fun `Attribute value should be be implicitly-tagged SEQUENCE`() {
            val attributeValue = metadata.encode()

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
            val attributeValue = metadata.encode()

            val serviceOid = ASN1Utils.getOID(attributeValue.getObjectAt(0) as ASN1TaggedObject)
            serviceOid shouldBe SERVICE_OID
        }

        @Test
        fun `Validity period should be output as SEQUENCE`() {
            val attributeValue = metadata.encode()

            val validityPeriod = attributeValue.getObjectAt(1)
            shouldNotThrowAny {
                ASN1Sequence.getInstance(validityPeriod as ASN1TaggedObject, false)
            }
        }

        @Test
        fun `Start date should be included in validity period`() {
            val attributeValue = metadata.encode()

            val validityPeriodSequence = ASN1Sequence.getInstance(
                attributeValue.getObjectAt(1) as ASN1TaggedObject,
                false,
            )
            val startDate = DERGeneralizedTime.getInstance(
                validityPeriodSequence.getObjectAt(0) as ASN1TaggedObject?,
                false,
            )
            startDate shouldBe validityPeriod.start.toGeneralizedTime()
        }

        @Test
        fun `End date should be included in validity period`() {
            val attributeValue = metadata.encode()

            val validityPeriodSequence = ASN1Sequence.getInstance(
                attributeValue.getObjectAt(1) as ASN1TaggedObject,
                false,
            )
            val endDate = DERGeneralizedTime.getInstance(
                validityPeriodSequence.getObjectAt(1) as ASN1TaggedObject?,
                false,
            )
            endDate shouldBe validityPeriod.endInclusive.toGeneralizedTime()
        }
    }

    @Nested
    inner class Decode {
        @Test
        fun `Metadata should have at least 2 items`() {
            val attributeValue = ASN1Utils.makeSequence(listOf(SERVICE_OID), false)

            val exception = shouldThrow<SignatureException> {
                SignatureMetadata.decode(attributeValue)
            }

            exception.message shouldBe "Metadata SEQUENCE should have at least 2 items (got 1)"
        }

        @Test
        fun `Service should be set to a valid OID`() {
            val invalidOid = DERNull.INSTANCE
            val attributeValue =
                ASN1Utils.makeSequence(listOf(invalidOid, validityPeriod.encode()), false)

            val exception = shouldThrow<SignatureException> {
                SignatureMetadata.decode(attributeValue)
            }

            exception.message shouldBe "Service in metadata isn't an OID"
            exception.cause should beInstanceOf<ASN1Exception>()
        }

        @Nested
        inner class PeriodValidation {
            @Test
            fun `Validity period should be a SEQUENCE`() {
                val invalidPeriod = DERNull.INSTANCE
                val attributeValue =
                    ASN1Utils.makeSequence(listOf(SERVICE_OID, invalidPeriod), false)

                val exception = shouldThrow<SignatureException> {
                    SignatureMetadata.decode(attributeValue)
                }

                exception.message shouldBe "Validity period in metadata isn't a SEQUENCE"
                exception.cause should beInstanceOf<IllegalStateException>()
            }

            @Test
            fun `Validity period should have at least 2 items`() {
                val invalidPeriod = ASN1Utils.makeSequence(listOf(DERNull.INSTANCE))
                val attributeValue =
                    ASN1Utils.makeSequence(listOf(SERVICE_OID, invalidPeriod), false)

                val exception = shouldThrow<SignatureException> {
                    SignatureMetadata.decode(attributeValue)
                }

                exception.message shouldBe
                    "Validity period in metadata should have at least 2 items (got 1)"
            }

            @Test
            fun `Start date should be a GeneralizedTime`() {
                val invalidStartDate = DERNull.INSTANCE
                val invalidPeriod = ASN1Utils.makeSequence(
                    listOf(
                        invalidStartDate,
                        validityPeriod.endInclusive.toGeneralizedTime(),
                    ),
                    false,
                )
                val attributeValue =
                    ASN1Utils.makeSequence(listOf(SERVICE_OID, invalidPeriod), false)

                val exception = shouldThrow<SignatureException> {
                    SignatureMetadata.decode(attributeValue)
                }

                exception.message shouldBe "Start date in metadata is invalid"
                exception.cause should beInstanceOf<ASN1Exception>()
            }

            @Test
            fun `End date should be a GeneralizedTime`() {
                val invalidEndDate = DERNull.INSTANCE
                val invalidPeriod = ASN1Utils.makeSequence(
                    listOf(
                        validityPeriod.start.toGeneralizedTime(),
                        invalidEndDate,
                    ),
                    false,
                )
                val attributeValue =
                    ASN1Utils.makeSequence(listOf(SERVICE_OID, invalidPeriod), false)

                val exception = shouldThrow<SignatureException> {
                    SignatureMetadata.decode(attributeValue)
                }

                exception.message shouldBe "End date in metadata is invalid"
                exception.cause should beInstanceOf<ASN1Exception>()
            }
        }

        @Test
        fun `Valid metadata should use have service OID extracted`() {
            val attribute = metadata.encode()

            val decodedMetadata = SignatureMetadata.decode(attribute)

            decodedMetadata.service shouldBe SERVICE_OID
        }

        @Test
        fun `Valid metadata should use have validity period extracted`() {
            val attribute = metadata.encode()

            val decodedMetadata = SignatureMetadata.decode(attribute)

            decodedMetadata.validityPeriod shouldBe validityPeriod
        }
    }
}
