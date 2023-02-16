package tech.relaycorp.veraid.dns

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.KeyAlgorithm
import tech.relaycorp.veraid.OrganisationKeySpec
import tech.relaycorp.veraid.SERVICE_OID

class VeraRdataFieldsTest {
    private val orgKeyAlgorithm = KeyAlgorithm.RSA_2048
    private val orgKeyAlgorithmId = orgKeyAlgorithm.typeId
    private val orgKeyId = "org-key-id"
    private val ttlOverride = 2.days
    private val ttlOverrideSeconds = ttlOverride.inWholeSeconds
    private val service = SERVICE_OID

    @Nested
    inner class Parse {
        @Test
        fun `There should be at least 3 space-separated fields`() {
            val exception = shouldThrow<InvalidRdataException> {
                VeraRdataFields.parse("$orgKeyAlgorithmId $orgKeyId")
            }

            exception.message shouldBe "RDATA should have at least 3 space-separated fields (got 2)"
        }

        @Nested
        inner class OrgKeyAlgorithm {
            @Test
            fun `Malformed key algorithm should be refused`() {
                val invalidKeyAlgorithm = "not-an-integer"

                val exception = shouldThrow<InvalidRdataException> {
                    VeraRdataFields.parse("$invalidKeyAlgorithm $orgKeyId $ttlOverride")
                }

                exception.message shouldBe "Malformed algorithm id ($invalidKeyAlgorithm)"
            }

            @Test
            fun `Non-existing key algorithm should be refused`() {
                val invalidKeyAlgorithm = 0

                val exception = shouldThrow<InvalidRdataException> {
                    VeraRdataFields.parse("$invalidKeyAlgorithm $orgKeyId $ttlOverride")
                }

                exception.message shouldBe "Unknown algorithm id ($invalidKeyAlgorithm)"
            }
        }

        @Nested
        inner class TtlOverride {
            @Test
            fun `Non-integer value should be refused`() {
                val invalidTtlOverride = 4.5

                val exception = shouldThrow<InvalidRdataException> {
                    VeraRdataFields.parse("$orgKeyAlgorithmId $orgKeyId $invalidTtlOverride")
                }

                exception.message shouldBe "Malformed TTL override ($invalidTtlOverride)"
            }

            @Test
            fun `Negative value should be refused`() {
                val invalidTtlOverride = -1

                val exception = shouldThrow<InvalidRdataException> {
                    VeraRdataFields.parse("$orgKeyAlgorithmId $orgKeyId $invalidTtlOverride")
                }

                exception.message shouldBe "Malformed TTL override ($invalidTtlOverride)"
            }

            @Test
            fun `90 days should be allowed`() {
                val ninetyDays = 90.days

                val fields = VeraRdataFields.parse(
                    "$orgKeyAlgorithmId $orgKeyId ${ninetyDays.inWholeSeconds}"
                )

                fields.ttlOverride shouldBe ninetyDays
            }

            @Test
            fun `TTL should be capped at 90 days`() {
                val ninetyDays = 90.days
                val over90Days = ninetyDays + 1.milliseconds

                val fields = VeraRdataFields.parse(
                    "$orgKeyAlgorithmId $orgKeyId ${over90Days.inWholeSeconds}"
                )

                fields.ttlOverride shouldBe ninetyDays
            }
        }

        @Test
        fun `Fields should be output if value is valid`() {
            val fields = VeraRdataFields.parse("$orgKeyAlgorithmId $orgKeyId $ttlOverrideSeconds")

            fields shouldBe VeraRdataFields(
                OrganisationKeySpec(KeyAlgorithm[orgKeyAlgorithmId]!!, orgKeyId),
                ttlOverride,
            )
        }

        @Nested
        inner class ServiceOid {
            @Test
            fun `Service OID should be absent if unspecified`() {
                val fields =
                    VeraRdataFields.parse("$orgKeyAlgorithmId $orgKeyId $ttlOverrideSeconds")

                fields.service shouldBe null
            }

            @Test
            fun `Malformed service OID should be refused`() {
                val malformedServiceOid = "SERVICE"

                val exception = shouldThrow<InvalidRdataException> {
                    VeraRdataFields.parse(
                        "$orgKeyAlgorithmId $orgKeyId $ttlOverrideSeconds $malformedServiceOid"
                    )
                }

                exception.message shouldBe "Malformed service OID ($malformedServiceOid)"
            }

            @Test
            fun `Service OID should be present if specified`() {
                val fields = VeraRdataFields.parse(
                    "$orgKeyAlgorithmId $orgKeyId $ttlOverrideSeconds ${service.id}"
                )

                fields.service shouldBe service
            }
        }

        @Nested
        inner class ExtraneousWhitespace {
            private val expectedFields = VeraRdataFields(
                OrganisationKeySpec(KeyAlgorithm[orgKeyAlgorithmId]!!, orgKeyId),
                ttlOverride,
            )

            @Test
            fun `Leading whitespace should be ignored`() {
                val fields =
                    VeraRdataFields.parse(" \t $orgKeyAlgorithmId $orgKeyId $ttlOverrideSeconds")

                fields shouldBe expectedFields
            }

            @Test
            fun `Trailing whitespace should be ignored`() {
                val fields =
                    VeraRdataFields.parse("$orgKeyAlgorithmId $orgKeyId $ttlOverrideSeconds \t ")

                fields shouldBe expectedFields
            }

            @Test
            fun `Extra whitespace in separator should be ignored`() {
                val fields =
                    VeraRdataFields.parse("$orgKeyAlgorithmId  \t $orgKeyId $ttlOverrideSeconds")

                fields shouldBe expectedFields
            }
        }
    }

    @Nested
    inner class ToString {
        private val fields = VeraRdataFields(
            OrganisationKeySpec(orgKeyAlgorithm, orgKeyId),
            ttlOverride,
        )

        @Test
        fun `Key algorithm should be the first field`() {
            val string = fields.toString()

            string.split(" ")[0] shouldBe orgKeyAlgorithmId.toString()
        }

        @Test
        fun `Key id should be the second field`() {
            val string = fields.toString()

            string.split(" ")[1] shouldBe orgKeyId
        }

        @Test
        fun `TTL override should be the third field`() {
            val string = fields.toString()

            string.split(" ")[2] shouldBe ttlOverrideSeconds.toString()
        }

        @Test
        fun `Service OID should be absent if unset`() {
            val fieldsWithoutService = fields.copy(service = null)

            val string = fieldsWithoutService.toString()

            string.split(" ") shouldHaveSize 3
        }

        @Test
        fun `Service OID should be fourth field if set`() {
            val fieldsWithService = fields.copy(service = service)

            val string = fieldsWithService.toString()

            string.split(" ")[3] shouldBe service.id
        }
    }
}
