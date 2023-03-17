package tech.relaycorp.veraid

import io.kotest.matchers.date.shouldBeAfter
import io.kotest.matchers.date.shouldBeBefore
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.beInstanceOf
import io.kotest.matchers.types.instanceOf
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.ContentInfo
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.veraid.dns.InvalidChainException
import tech.relaycorp.veraid.dns.RECORD
import tech.relaycorp.veraid.dns.VeraDnssecChain
import tech.relaycorp.veraid.dns.makeResponse
import tech.relaycorp.veraid.pki.MemberIdBundle
import tech.relaycorp.veraid.utils.asn1.ASN1Exception
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
import tech.relaycorp.veraid.utils.cms.SignedData
import tech.relaycorp.veraid.utils.cms.SignedDataException
import tech.relaycorp.veraid.utils.x509.Certificate
import tech.relaycorp.veraid.utils.x509.CertificateException
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit
import tech.relaycorp.veraid.utils.asn1.toDlTaggedObject

class SignatureBundleTest {
    private val response = RECORD.makeResponse()
    private val veraDnssecChain = VeraDnssecChain(ORG_NAME, listOf(response))
    private val memberIdBundle = MemberIdBundle(veraDnssecChain, ORG_CERT, MEMBER_CERT)
    private val validityPeriod = MEMBER_CERT.validityPeriod

    private val plaintext = "the plaintext".toByteArray()

    @Nested
    inner class Generate {
        private val signatureExpiry =
            validityPeriod.endInclusive.withZoneSameInstant(ZoneOffset.UTC)

        @Test
        fun `DNSSEC chain should be attached`() {
            val signatureBundle = SignatureBundle.generate(
                plaintext,
                SERVICE_OID.id,
                memberIdBundle,
                MEMBER_KEY_PAIR.private,
                validityPeriod.endInclusive,
            )

            signatureBundle.memberIdBundle.dnssecChain shouldBe veraDnssecChain
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

            signatureBundle.memberIdBundle.orgCertificate shouldBe ORG_CERT
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
                    validityPeriod.start.withZoneSameInstant(ZoneOffset.UTC)
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
                        metadataAttribute!!.attrValues!!.getObjectAt(0).toDlTaggedObject(false),
                    )
                }
        }
    }

    @Nested
    inner class Serialise {
        private val signedData = SignedData.sign(plaintext, MEMBER_KEY_PAIR.private, MEMBER_CERT)

        @Test
        fun `Version should be 0`() {
            val bundle = SignatureBundle(memberIdBundle, signedData)

            val serialisation = bundle.serialise()

            val sequence = ASN1Sequence.getInstance(serialisation)
            val versionRaw = sequence.getObjectAt(0)
            ASN1Integer.getInstance(versionRaw as ASN1TaggedObject, false) shouldBe ASN1Integer(0)
        }

        @Test
        fun `DNSSEC chain should be attached`() {
            val bundle = SignatureBundle(memberIdBundle, signedData)

            val serialisation = bundle.serialise()

            val sequence = ASN1Sequence.getInstance(serialisation)
            val chainRaw = sequence.getObjectAt(1)
            val chainSet = DERSet.getInstance(chainRaw as ASN1TaggedObject, false)
            chainSet.encoded shouldBe veraDnssecChain.encode().encoded
        }

        @Test
        fun `Organisation certificate should be attached`() {
            val bundle = SignatureBundle(memberIdBundle, signedData)

            val serialisation = bundle.serialise()

            val sequence = ASN1Sequence.getInstance(serialisation)
            val orgCertRaw = sequence.getObjectAt(2)
            val orgCertSequence = ASN1Sequence.getInstance(orgCertRaw as ASN1TaggedObject, false)
            orgCertSequence.encoded shouldBe ORG_CERT.certificateHolder.encoded
        }

        @Test
        fun `SignedData should be attached`() {
            val bundle = SignatureBundle(memberIdBundle, signedData)

            val serialisation = bundle.serialise()

            val sequence = ASN1Sequence.getInstance(serialisation)
            val signedDataRaw = sequence.getObjectAt(3)
            val signedDataSequence =
                ContentInfo.getInstance(signedDataRaw as ASN1TaggedObject, false)
            signedDataSequence shouldBe signedData.encode()
        }
    }

    @Nested
    inner class Deserialise {
        private val bundleVersion = ASN1Integer(0)
        private val signedData = SignedData.sign(
            plaintext,
            MEMBER_KEY_PAIR.private,
            MEMBER_CERT,
            encapsulatedCertificates = setOf(MEMBER_CERT),
        )

        @Test
        fun `Serialisation should be a SEQUENCE`() {
            val malformedBundle = DERNull.INSTANCE.encoded

            val exception = assertThrows<SignatureException> {
                SignatureBundle.deserialise(malformedBundle)
            }

            exception.message shouldBe "Signature bundle should be a SEQUENCE"
            exception.cause should beInstanceOf<ASN1Exception>()
        }

        @Test
        fun `SEQUENCE should have at least 4 items`() {
            val malformedBundle = ASN1Utils.serializeSequence(
                listOf(
                    bundleVersion,
                    veraDnssecChain.encode(),
                    ORG_CERT.encode(),
                ),
                false,
            )

            val exception = assertThrows<SignatureException> {
                SignatureBundle.deserialise(malformedBundle)
            }

            exception.message shouldBe "Signature bundle should have at least 4 items"
        }

        @Test
        fun `Malformed DNSSEC chain should be refused`() {
            val malformedBundle = ASN1Utils.serializeSequence(
                listOf(
                    bundleVersion,
                    DERNull.INSTANCE, // Malformed
                    ORG_CERT.encode(),
                    signedData.encode(),
                ),
                false,
            )

            val exception = assertThrows<SignatureException> {
                SignatureBundle.deserialise(malformedBundle)
            }

            exception.message shouldBe "VeraId DNSSEC chain is malformed"
            exception.cause shouldBe instanceOf<InvalidChainException>()
        }

        @Test
        fun `Malformed organisation certificate should be refused`() {
            val malformedBundle = ASN1Utils.serializeSequence(
                listOf(
                    bundleVersion,
                    veraDnssecChain.encode(),
                    DERNull.INSTANCE, // Malformed
                    signedData.encode(),
                ),
                false,
            )

            val exception = assertThrows<SignatureException> {
                SignatureBundle.deserialise(malformedBundle)
            }

            exception.message shouldBe "Organisation certificate is malformed"
            exception.cause shouldBe instanceOf<CertificateException>()
        }

        @Test
        fun `Malformed SignedData should be refused`() {
            val malformedBundle = ASN1Utils.serializeSequence(
                listOf(
                    bundleVersion,
                    veraDnssecChain.encode(),
                    ORG_CERT.encode(),
                    DERNull.INSTANCE, // Malformed
                ),
                false,
            )

            val exception = assertThrows<SignatureException> {
                SignatureBundle.deserialise(malformedBundle)
            }

            exception.message shouldBe "SignedData is malformed"
            exception.cause shouldBe instanceOf<SignedDataException>()
        }

        @Test
        fun `SignedData should have signer certificate attached`() {
            val incompleteSignedData = SignedData.sign(
                plaintext,
                MEMBER_KEY_PAIR.private,
                MEMBER_CERT,
            )
            val invalidBundle = ASN1Utils.serializeSequence(
                listOf(
                    bundleVersion,
                    veraDnssecChain.encode(),
                    ORG_CERT.encode(),
                    incompleteSignedData.encode(),
                ),
                false,
            )

            val exception = assertThrows<SignatureException> {
                SignatureBundle.deserialise(invalidBundle)
            }

            exception.message shouldBe "SignedData should have signer certificate attached"
        }

        @Test
        fun `Bundle should be returned if serialisation is well-formed`() {
            val bundle = SignatureBundle(memberIdBundle, signedData)
            val serialisation = bundle.serialise()

            val deserialisedBundle = SignatureBundle.deserialise(serialisation)

            deserialisedBundle.serialise() shouldBe bundle.serialise()
        }

        @Test
        fun `DNSSEC chain should take organisation name from organisation certificate`() {
            val bundle = ASN1Utils.serializeSequence(
                listOf(
                    bundleVersion,
                    veraDnssecChain.encode(),
                    ORG_CERT.encode(),
                    signedData.encode(),
                ),
                false,
            )

            val deserialisedBundle = SignatureBundle.deserialise(bundle)

            deserialisedBundle.memberIdBundle.dnssecChain.orgName shouldBe ORG_CERT.commonName
        }
    }
}
