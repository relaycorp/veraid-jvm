package tech.relaycorp.vera.pki

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.date.shouldBeBefore
import io.kotest.matchers.date.shouldNotBeBefore
import io.kotest.matchers.shouldBe
import java.math.BigInteger
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit
import org.bouncycastle.asn1.x509.BasicConstraints
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.vera.MEMBER_KEY_PAIR
import tech.relaycorp.vera.MEMBER_NAME
import tech.relaycorp.vera.ORG_KEY_PAIR
import tech.relaycorp.vera.ORG_NAME

class MemberCertificateTest {
    @Nested
    inner class Issue {
        private val expiryDate = ZonedDateTime.now().plusMinutes(60).truncatedTo(ChronoUnit.SECONDS)
        private val orgCertificate = OrgCertificate.selfIssue(ORG_NAME, ORG_KEY_PAIR, expiryDate)

        @Nested
        inner class MemberName {
            private val validationErrorMessage =
                "User name should not contain at signs or whitespace other than simple spaces"

            @Test
            fun `should be the at sign if member is a bot`() {
                val cert = MemberCertificate.issue(
                    null,
                    MEMBER_KEY_PAIR.public,
                    orgCertificate,
                    ORG_KEY_PAIR.private,
                    expiryDate,
                )

                cert.commonName shouldBe "@"
            }

            @Test
            fun `should be the specified name if set`() {
                val cert = MemberCertificate.issue(
                    MEMBER_NAME,
                    MEMBER_KEY_PAIR.public,
                    orgCertificate,
                    ORG_KEY_PAIR.private,
                    expiryDate,
                )

                cert.commonName shouldBe MEMBER_NAME
            }

            @Test
            fun `should not contain at signs`() {
                val exception = shouldThrow<PKIException> {
                    MemberCertificate.issue(
                        "@$MEMBER_NAME",
                        MEMBER_KEY_PAIR.public,
                        orgCertificate,
                        ORG_KEY_PAIR.private,
                        expiryDate,
                    )
                }

                exception.message shouldBe validationErrorMessage
            }

            @Test
            fun `should not contain tabs`() {
                val exception = shouldThrow<PKIException> {
                    MemberCertificate.issue(
                        "\t$MEMBER_NAME",
                        MEMBER_KEY_PAIR.public,
                        orgCertificate,
                        ORG_KEY_PAIR.private,
                        expiryDate,
                    )
                }

                exception.message shouldBe validationErrorMessage
            }

            @Test
            fun `should not contain carriage returns`() {
                val exception = shouldThrow<PKIException> {
                    MemberCertificate.issue(
                        "\r$MEMBER_NAME",
                        MEMBER_KEY_PAIR.public,
                        orgCertificate,
                        ORG_KEY_PAIR.private,
                        expiryDate,
                    )
                }

                exception.message shouldBe validationErrorMessage
            }

            @Test
            fun `should not contain line feeds`() {
                val exception = shouldThrow<PKIException> {
                    MemberCertificate.issue(
                        "\n$MEMBER_NAME",
                        MEMBER_KEY_PAIR.public,
                        orgCertificate,
                        ORG_KEY_PAIR.private,
                        expiryDate,
                    )
                }

                exception.message shouldBe validationErrorMessage
            }
        }

        @Test
        fun `Member public key should be honoured`() {
            val cert = MemberCertificate.issue(
                MEMBER_NAME,
                MEMBER_KEY_PAIR.public,
                orgCertificate,
                ORG_KEY_PAIR.private,
                expiryDate,
            )

            cert.subjectPublicKey shouldBe MEMBER_KEY_PAIR.public
        }

        @Test
        fun `Certificate should be issued by organisation`() {
            val cert = MemberCertificate.issue(
                MEMBER_NAME,
                MEMBER_KEY_PAIR.public,
                orgCertificate,
                ORG_KEY_PAIR.private,
                expiryDate,
            )

            cert.getCertificationPath(emptyList(), listOf(orgCertificate)) shouldHaveSize 2
        }

        @Test
        fun `Expiry date should match specified one`() {
            val cert = MemberCertificate.issue(
                MEMBER_NAME,
                MEMBER_KEY_PAIR.public,
                orgCertificate,
                ORG_KEY_PAIR.private,
                expiryDate,
            )

            cert.expiryDate shouldBe expiryDate
        }

        @Nested
        inner class StartDate {
            @Test
            fun `should default to now`() {
                val beforeIssuance = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS)

                val cert = MemberCertificate.issue(
                    MEMBER_NAME,
                    MEMBER_KEY_PAIR.public,
                    orgCertificate,
                    ORG_KEY_PAIR.private,
                    expiryDate,
                )

                val afterIssuance = ZonedDateTime.now()
                cert.startDate shouldNotBeBefore beforeIssuance
                cert.startDate shouldBeBefore afterIssuance
            }

            @Test
            fun `should match explicit date if set`() {
                val startDate = expiryDate.minusSeconds(2)

                val cert = MemberCertificate.issue(
                    MEMBER_NAME,
                    MEMBER_KEY_PAIR.public,
                    orgCertificate,
                    ORG_KEY_PAIR.private,
                    expiryDate,
                    startDate,
                )

                cert.startDate shouldBe startDate
            }
        }

        @Nested
        inner class BasicConstraintsExtension {
            @Test
            fun `Subject should not be a CA`() {
                val cert = MemberCertificate.issue(
                    MEMBER_NAME,
                    MEMBER_KEY_PAIR.public,
                    orgCertificate,
                    ORG_KEY_PAIR.private,
                    expiryDate,
                )

                cert.isCA shouldBe false
            }

            @Test
            fun `Path length should be zero`() {
                val cert = MemberCertificate.issue(
                    MEMBER_NAME,
                    MEMBER_KEY_PAIR.public,
                    orgCertificate,
                    ORG_KEY_PAIR.private,
                    expiryDate,
                )

                val basicConstraints =
                    BasicConstraints.fromExtensions(cert.certificateHolder.extensions)
                basicConstraints.pathLenConstraint shouldBe BigInteger.ZERO
            }
        }
    }
}