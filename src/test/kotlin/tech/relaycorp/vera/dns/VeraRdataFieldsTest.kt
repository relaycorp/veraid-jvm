package tech.relaycorp.vera.dns

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.vera.KeyAlgorithm
import tech.relaycorp.vera.OrganisationKeySpec

class VeraRdataFieldsTest {
    @Nested
    inner class Parse {
        private val orgKeyAlgorithm = KeyAlgorithm.RSA_2048.typeId
        private val orgKeyId = "org-key-id"
        private val ttlOverride = 2.days
        private val ttlOverrideSeconds = ttlOverride.inWholeSeconds
        private val service = VeraStubs.SERVICE_OID

        @Test
        fun `There should be at least 3 space-separated fields`() {
            val exception = shouldThrow<InvalidRdataException> {
                VeraRdataFields.parse("$orgKeyAlgorithm $orgKeyId")
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
                    VeraRdataFields.parse("$orgKeyAlgorithm $orgKeyId $invalidTtlOverride")
                }

                exception.message shouldBe "Malformed TTL override ($invalidTtlOverride)"
            }

            @Test
            fun `Negative value should be refused`() {
                val invalidTtlOverride = -1

                val exception = shouldThrow<InvalidRdataException> {
                    VeraRdataFields.parse("$orgKeyAlgorithm $orgKeyId $invalidTtlOverride")
                }

                exception.message shouldBe "Malformed TTL override ($invalidTtlOverride)"
            }

            @Test
            fun `90 days should be allowed`() {
                val ninetyDays = 90.days

                val fields = VeraRdataFields.parse(
                    "$orgKeyAlgorithm $orgKeyId ${ninetyDays.inWholeSeconds}"
                )

                fields.ttlOverride shouldBe ninetyDays
            }

            @Test
            fun `TTL should be capped at 90 days`() {
                val ninetyDays = 90.days
                val over90Days = ninetyDays + 1.milliseconds

                val fields = VeraRdataFields.parse(
                    "$orgKeyAlgorithm $orgKeyId ${over90Days.inWholeSeconds}"
                )

                fields.ttlOverride shouldBe ninetyDays
            }
        }

        @Test
        fun `Fields should be output if value is valid`() {
            val fields = VeraRdataFields.parse("$orgKeyAlgorithm $orgKeyId $ttlOverrideSeconds")

            fields shouldBe VeraRdataFields(
                OrganisationKeySpec(KeyAlgorithm[orgKeyAlgorithm]!!, orgKeyId),
                ttlOverride,
            )
        }

        @Nested
        inner class ServiceOid {
            @Test
            fun `Service OID should be absent if unspecified`() {
                val fields = VeraRdataFields.parse("$orgKeyAlgorithm $orgKeyId $ttlOverrideSeconds")

                fields.service shouldBe null
            }

            @Test
            fun `Malformed service OID should be refused`() {
                val malformedServiceOid = "SERVICE"

                val exception = shouldThrow<InvalidRdataException> {
                    VeraRdataFields.parse(
                        "$orgKeyAlgorithm $orgKeyId $ttlOverrideSeconds $malformedServiceOid"
                    )
                }

                exception.message shouldBe "Malformed service OID ($malformedServiceOid)"
            }

            @Test
            fun `Service OID should be present if specified`() {
                val fields = VeraRdataFields.parse(
                    "$orgKeyAlgorithm $orgKeyId $ttlOverrideSeconds ${service.id}"
                )

                fields.service shouldBe service
            }
        }

        @Nested
        inner class ExtraneousWhitespace {
            private val expectedFields = VeraRdataFields(
                OrganisationKeySpec(KeyAlgorithm[orgKeyAlgorithm]!!, orgKeyId),
                ttlOverride,
            )

            @Test
            fun `Leading whitespace should be ignored`() {
                val fields =
                    VeraRdataFields.parse(" \t $orgKeyAlgorithm $orgKeyId $ttlOverrideSeconds")

                fields shouldBe expectedFields
            }

            @Test
            fun `Trailing whitespace should be ignored`() {
                val fields =
                    VeraRdataFields.parse("$orgKeyAlgorithm $orgKeyId $ttlOverrideSeconds \t ")

                fields shouldBe expectedFields
            }

            @Test
            fun `Extra whitespace in separator should be ignored`() {
                val fields =
                    VeraRdataFields.parse("$orgKeyAlgorithm  \t $orgKeyId $ttlOverrideSeconds")

                fields shouldBe expectedFields
            }
        }
    }
}
