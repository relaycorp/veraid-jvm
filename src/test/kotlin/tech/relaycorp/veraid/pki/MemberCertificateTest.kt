package tech.relaycorp.veraid.pki

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.date.shouldBeBefore
import io.kotest.matchers.date.shouldNotBeBefore
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.x509.BasicConstraints
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.MEMBER_CERT
import tech.relaycorp.veraid.MEMBER_KEY_PAIR
import tech.relaycorp.veraid.ORG_CERT
import tech.relaycorp.veraid.ORG_KEY_PAIR
import tech.relaycorp.veraid.USER_NAME
import java.math.BigInteger
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit

class MemberCertificateTest {
    @Nested
    inner class UserName {
        @Test
        fun `Name should be output if member is a user`() {
            val memberCertificate = MemberCertificate(MEMBER_CERT.certificateHolder)

            memberCertificate.userName shouldBe USER_NAME
        }

        @Test
        fun `Name should be null if member is a bot`() {
            val cert = MemberCertificate.issue(
                null,
                MEMBER_KEY_PAIR.public,
                ORG_CERT,
                ORG_KEY_PAIR.private,
                ORG_CERT.validityPeriod.endInclusive,
            )

            cert.userName shouldBe null
        }
    }

    @Nested
    inner class Issue {
        private val orgCertificate = OrgCertificate(ORG_CERT.certificateHolder)
        private val expiryDate = ORG_CERT.validityPeriod.endInclusive

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
                    USER_NAME,
                    MEMBER_KEY_PAIR.public,
                    orgCertificate,
                    ORG_KEY_PAIR.private,
                    expiryDate,
                )

                cert.commonName shouldBe USER_NAME
            }

            @Test
            fun `should not contain at signs`() {
                val exception = shouldThrow<PkiException> {
                    MemberCertificate.issue(
                        "@$USER_NAME",
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
                val exception = shouldThrow<PkiException> {
                    MemberCertificate.issue(
                        "\t$USER_NAME",
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
                val exception = shouldThrow<PkiException> {
                    MemberCertificate.issue(
                        "\r$USER_NAME",
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
                val exception = shouldThrow<PkiException> {
                    MemberCertificate.issue(
                        "\n$USER_NAME",
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
                USER_NAME,
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
                USER_NAME,
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
                USER_NAME,
                MEMBER_KEY_PAIR.public,
                orgCertificate,
                ORG_KEY_PAIR.private,
                expiryDate,
            )

            cert.validityPeriod.endInclusive shouldBe expiryDate
        }

        @Nested
        inner class StartDate {
            @Test
            fun `should default to now`() {
                val beforeIssuance = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS)

                val cert = MemberCertificate.issue(
                    USER_NAME,
                    MEMBER_KEY_PAIR.public,
                    orgCertificate,
                    ORG_KEY_PAIR.private,
                    expiryDate,
                )

                val afterIssuance = ZonedDateTime.now()
                cert.validityPeriod.start shouldNotBeBefore beforeIssuance
                cert.validityPeriod.start shouldBeBefore afterIssuance
            }

            @Test
            fun `should match explicit date if set`() {
                val startDate = expiryDate.minusSeconds(2)

                val cert = MemberCertificate.issue(
                    USER_NAME,
                    MEMBER_KEY_PAIR.public,
                    orgCertificate,
                    ORG_KEY_PAIR.private,
                    expiryDate,
                    startDate,
                )

                cert.validityPeriod.start shouldBe startDate
            }
        }

        @Nested
        inner class BasicConstraintsExtension {
            @Test
            fun `Subject should not be a CA`() {
                val cert = MemberCertificate.issue(
                    USER_NAME,
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
                    USER_NAME,
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
