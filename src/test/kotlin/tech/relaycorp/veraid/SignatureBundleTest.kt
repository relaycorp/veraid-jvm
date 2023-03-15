package tech.relaycorp.veraid

import io.kotest.matchers.date.shouldBeAfter
import io.kotest.matchers.date.shouldBeBefore
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.ASN1Sequence
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.dns.RECORD
import tech.relaycorp.veraid.dns.VeraDnssecChain
import tech.relaycorp.veraid.dns.makeResponse
import tech.relaycorp.veraid.pki.MemberIdBundle
import tech.relaycorp.veraid.utils.cms.SignedData
import tech.relaycorp.veraid.utils.x509.Certificate
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit

class SignatureBundleTest {
    @Nested
    inner class Generate {
        private val response = RECORD.makeResponse()
        private val veraDnssecChain = VeraDnssecChain(ORG_NAME, listOf(response))
        private val memberIdBundle = MemberIdBundle(veraDnssecChain, ORG_CERT, MEMBER_CERT)

        private val plaintext = "the plaintext".toByteArray()

        private val signatureExpiry =
            MEMBER_CERT.validityPeriod.endInclusive.withZoneSameInstant(ZoneOffset.UTC)

        @Test
        fun `DNSSEC chain should be attached`() {
            val signatureBundle = SignatureBundle.generate(
                plaintext,
                SERVICE_OID.id,
                memberIdBundle,
                MEMBER_KEY_PAIR.private,
                MEMBER_CERT.validityPeriod.endInclusive,
            )

            signatureBundle.chain shouldBe veraDnssecChain
        }

        @Test
        fun `Organisation certificate should be attached`() {
            val signatureBundle = SignatureBundle.generate(
                plaintext,
                SERVICE_OID.id,
                memberIdBundle,
                MEMBER_KEY_PAIR.private,
                signatureExpiry,
            )

            signatureBundle.orgCertificate shouldBe ORG_CERT
        }

        @Nested
        inner class Signature {
            @Test
            fun `Plaintext should be signed with specified private key`() {
                val signatureBundle = SignatureBundle.generate(
                    plaintext,
                    SERVICE_OID.id,
                    memberIdBundle,
                    MEMBER_KEY_PAIR.private,
                    signatureExpiry,
                )

                signatureBundle.signedData.verify(plaintext)
                signatureBundle.signedData.signerCertificate shouldBe
                    Certificate(MEMBER_CERT.certificateHolder)
            }

            @Test
            fun `Member certificate should be attached`() {
                val signatureBundle = SignatureBundle.generate(
                    plaintext,
                    SERVICE_OID.id,
                    memberIdBundle,
                    MEMBER_KEY_PAIR.private,
                    signatureExpiry,
                )

                signatureBundle.signedData.signerCertificate shouldBe
                    Certificate(MEMBER_CERT.certificateHolder)
            }

            @Test
            fun `Plaintext should be detached`() {
                val signatureBundle = SignatureBundle.generate(
                    plaintext,
                    SERVICE_OID.id,
                    memberIdBundle,
                    MEMBER_KEY_PAIR.private,
                    signatureExpiry,
                )

                signatureBundle.signedData.plaintext shouldBe null
            }
        }

        @Nested
        inner class SignatureMetadataAttribute {
            @Test
            fun `Metadata attribute should be present`() {
                val signatureBundle = SignatureBundle.generate(
                    plaintext,
                    SERVICE_OID.id,
                    memberIdBundle,
                    MEMBER_KEY_PAIR.private,
                    signatureExpiry,
                )

                val signedAttrs = signatureBundle.signedData.signedAttrs
                val attribute = signedAttrs?.get(VeraOids.SIGNATURE_METADATA_ATTR)
                attribute?.attrValues?.size() shouldBe 1
            }

            @Test
            fun `Service OID should be attached`() {
                val signatureBundle = SignatureBundle.generate(
                    plaintext,
                    SERVICE_OID.id,
                    memberIdBundle,
                    MEMBER_KEY_PAIR.private,
                    signatureExpiry,
                )

                val metadata = signatureBundle.signedData.metadata
                metadata.service shouldBe SERVICE_OID
            }

            @Test
            fun `Expiry date should be attached`() {
                val signatureBundle = SignatureBundle.generate(
                    plaintext,
                    SERVICE_OID.id,
                    memberIdBundle,
                    MEMBER_KEY_PAIR.private,
                    signatureExpiry,
                )

                val metadata = signatureBundle.signedData.metadata
                metadata.validityPeriod.endInclusive shouldBe signatureExpiry
            }

            @Test
            fun `Start date should default to the current time`() {
                val beforeGeneration = ZonedDateTime.now().withZoneSameInstant(ZoneOffset.UTC)
                    .truncatedTo(ChronoUnit.SECONDS)

                val signatureBundle = SignatureBundle.generate(
                    plaintext,
                    SERVICE_OID.id,
                    memberIdBundle,
                    MEMBER_KEY_PAIR.private,
                    signatureExpiry,
                )

                val afterGeneration = ZonedDateTime.now()
                val metadata = signatureBundle.signedData.metadata
                metadata.validityPeriod.start shouldBeBefore afterGeneration
                metadata.validityPeriod.start shouldBeAfter beforeGeneration.minusSeconds(1)
            }

            @Test
            fun `Any explicit start date should be honoured`() {
                val signatureStart =
                    MEMBER_CERT.validityPeriod.start.withZoneSameInstant(ZoneOffset.UTC)
                        .plusSeconds(2)

                val signatureBundle = SignatureBundle.generate(
                    plaintext,
                    SERVICE_OID.id,
                    memberIdBundle,
                    MEMBER_KEY_PAIR.private,
                    signatureExpiry,
                    signatureStart,
                )

                val metadata = signatureBundle.signedData.metadata
                metadata.validityPeriod.start shouldBe signatureStart
            }

            private val SignedData.metadata: SignatureMetadata
                get() {
                    val signedAttrs = this.signedAttrs
                    val metadataAttribute = signedAttrs?.get(VeraOids.SIGNATURE_METADATA_ATTR)
                    return SignatureMetadata.decode(
                        metadataAttribute!!.attrValues!!.getObjectAt(0) as ASN1Sequence,
                    )
                }
        }
    }

    @Nested
    inner class Serialise {
        @Test
        @Disabled
        fun `Version should be 0`() {
        }
    }
}
