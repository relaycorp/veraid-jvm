package tech.relaycorp.veraid

import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.argumentCaptor
import com.nhaarman.mockitokotlin2.doNothing
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.verify
import com.nhaarman.mockitokotlin2.whenever
import io.kotest.matchers.comparables.shouldNotBeGreaterThan
import io.kotest.matchers.comparables.shouldNotBeLessThan
import io.kotest.matchers.date.shouldBeAfter
import io.kotest.matchers.date.shouldBeBefore
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.beInstanceOf
import io.kotest.matchers.types.instanceOf
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.ContentInfo
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.veraid.dns.InvalidChainException
import tech.relaycorp.veraid.dns.RECORD
import tech.relaycorp.veraid.dns.VeraDnssecChain
import tech.relaycorp.veraid.dns.makeResponse
import tech.relaycorp.veraid.pki.Member
import tech.relaycorp.veraid.pki.MemberIdBundle
import tech.relaycorp.veraid.pki.OrgCertificate
import tech.relaycorp.veraid.pki.PkiException
import tech.relaycorp.veraid.utils.asn1.ASN1Exception
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
import tech.relaycorp.veraid.utils.cms.SignedData
import tech.relaycorp.veraid.utils.cms.SignedDataException
import tech.relaycorp.veraid.utils.x509.Certificate
import tech.relaycorp.veraid.utils.x509.CertificateException
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit

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
                        metadataAttribute!!.attrValues!!.getObjectAt(0),
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

    @Nested
    inner class Verify {
        @Test
        fun breakIt() {
            2 shouldBe 1
        }

        private val validBundle = SignatureBundle.generate(
            plaintext,
            SERVICE_OID.id,
            memberIdBundle,
            MEMBER_KEY_PAIR.private,
            validityPeriod.endInclusive,
            validityPeriod.start,
        )

        @Test
        fun `Signature should correspond to specified plaintext`() = runTest {
            val otherPlaintext = "not".toByteArray() + plaintext

            val exception = assertThrows<SignatureException> {
                validBundle.verify(otherPlaintext, SERVICE_OID.id)
            }

            exception.message shouldBe "Signature is invalid"
            exception.cause shouldBe instanceOf<SignedDataException>()
        }

        @Test
        fun `Member id bundle should be valid`() = runTest {
            val invalidMemberIdBundle = MemberIdBundle(
                memberIdBundle.dnssecChain,
                OrgCertificate(MEMBER_CERT.certificateHolder), // Invalid
                MEMBER_CERT,
            )
            val invalidBundle = SignatureBundle(invalidMemberIdBundle, validBundle.signedData)

            val exception = assertThrows<SignatureException> {
                invalidBundle.verify(plaintext, SERVICE_OID.id)
            }

            exception.message shouldBe "Member id bundle is invalid"
            exception.cause shouldBe instanceOf<PkiException>()
        }

        @Nested
        inner class VerificationPeriod {
            @Test
            fun `End date should not be before start date`() = runTest {
                val now = ZonedDateTime.now()
                val invalidPeriod = now..now.minusSeconds(1)

                val exception = assertThrows<SignatureException> {
                    validBundle.verify(plaintext, SERVICE_OID.id, invalidPeriod)
                }

                exception.message shouldBe "Verification expiry date cannot be before start date"
            }

            @Test
            fun `Period should default to the current time`() = runTest {
                val memberIdBundleMock = mockMemberIdBundle()
                val bundle = SignatureBundle(memberIdBundleMock, validBundle.signedData)
                val beforeVerification = ZonedDateTime.now()

                bundle.verify(plaintext, SERVICE_OID.id)

                val afterVerification = ZonedDateTime.now()
                argumentCaptor<DatePeriod>().apply {
                    verify(memberIdBundleMock).verify(any(), capture())

                    firstValue.start shouldBe firstValue.endInclusive
                    firstValue.start shouldNotBeGreaterThan afterVerification
                    firstValue.start shouldNotBeLessThan beforeVerification
                }
            }

            @Test
            fun `Period as a single date should be supported`() = runTest {
                val memberIdBundleMock = mockMemberIdBundle()
                val bundle = SignatureBundle(memberIdBundleMock, validBundle.signedData)
                val verificationDate = ZonedDateTime.now()

                bundle.verify(plaintext, SERVICE_OID.id, verificationDate)

                argumentCaptor<DatePeriod>().apply {
                    verify(memberIdBundleMock).verify(any(), capture())

                    firstValue.start shouldBe verificationDate.withZoneSameInstant(ZoneOffset.UTC)
                    firstValue.endInclusive shouldBe
                        verificationDate.withZoneSameInstant(ZoneOffset.UTC)
                }
            }

            @Test
            fun `Period should overlap with that of signature`() = runTest {
                val metadata = SignatureMetadata(
                    SERVICE_OID,
                    validityPeriod.start..validityPeriod.start.plusSeconds(1),
                )
                val attribute = Attribute(
                    VeraOids.SIGNATURE_METADATA_ATTR,
                    DERSet(metadata.encode()),
                )
                val signedData = SignedData.sign(
                    plaintext,
                    MEMBER_KEY_PAIR.private,
                    MEMBER_CERT,
                    setOf(MEMBER_CERT),
                    encapsulatePlaintext = false,
                    extraSignedAttrs = setOf(attribute),
                )
                val bundle = SignatureBundle(mockMemberIdBundle(), signedData)

                val exception = assertThrows<SignatureException> {
                    bundle.verify(plaintext, SERVICE_OID.id, validityPeriod.endInclusive)
                }

                exception.message shouldBe "Signature period does not overlap with required period"
            }

            @Test
            fun `Period should overlap with that of member id bundle`() = runTest {
                val memberIdBundleMock = mockMemberIdBundle()
                val bundle = SignatureBundle(memberIdBundleMock, validBundle.signedData)
                val verificationPeriod =
                    validityPeriod.start.plusSeconds(1)..validityPeriod.endInclusive.plusSeconds(1)

                bundle.verify(plaintext, SERVICE_OID.id, verificationPeriod)

                argumentCaptor<DatePeriod>().apply {
                    verify(memberIdBundleMock).verify(any(), capture())

                    firstValue.start shouldBe
                        verificationPeriod.start.withZoneSameInstant(ZoneOffset.UTC)
                    firstValue.endInclusive shouldBe
                        validityPeriod.endInclusive.withZoneSameInstant(ZoneOffset.UTC)
                }
            }
        }

        @Nested
        inner class Metadata {
            private val otherService = SERVICE_OID.branch("1")

            @Test
            fun `Signed attributes should not be empty`() = runTest {
                val incompleteSignedData = mock<SignedData>()
                doNothing().whenever(incompleteSignedData).verify(plaintext)
                whenever(incompleteSignedData.signedAttrs).thenReturn(null)
                val incompleteBundle = SignatureBundle(mockMemberIdBundle(), incompleteSignedData)

                val exception = assertThrows<SignatureException> {
                    incompleteBundle.verify(plaintext, SERVICE_OID.id)
                }

                exception.message shouldBe "SignedData should have VeraId metadata attribute"
            }

            @Test
            fun `Attribute should be present in signature`() = runTest {
                val incompleteSignedData = SignedData.sign(
                    plaintext,
                    MEMBER_KEY_PAIR.private,
                    MEMBER_CERT,
                    setOf(MEMBER_CERT),
                    encapsulatePlaintext = false,
                )
                val incompleteBundle = SignatureBundle(mockMemberIdBundle(), incompleteSignedData)

                val exception = assertThrows<SignatureException> {
                    incompleteBundle.verify(plaintext, SERVICE_OID.id)
                }

                exception.message shouldBe "SignedData should have VeraId metadata attribute"
            }

            @Test
            fun `Attribute should have at least one value`() = runTest {
                val invalidValue = Attribute(
                    VeraOids.SIGNATURE_METADATA_ATTR,
                    DERSet(),
                )
                val invalidSignedData = SignedData.sign(
                    plaintext,
                    MEMBER_KEY_PAIR.private,
                    MEMBER_CERT,
                    setOf(MEMBER_CERT),
                    encapsulatePlaintext = false,
                    extraSignedAttrs = setOf(invalidValue),
                )
                val invalidBundle = SignatureBundle(mockMemberIdBundle(), invalidSignedData)

                val exception = assertThrows<SignatureException> {
                    invalidBundle.verify(plaintext, SERVICE_OID.id)
                }

                exception.message shouldBe "Metadata attribute should have at least one value"
            }

            @Test
            fun `Attribute should be well-formed`() = runTest {
                val malformedAttribute = Attribute(
                    VeraOids.SIGNATURE_METADATA_ATTR,
                    DERSet(DERNull.INSTANCE),
                )
                val invalidSignedData = SignedData.sign(
                    plaintext,
                    MEMBER_KEY_PAIR.private,
                    MEMBER_CERT,
                    setOf(MEMBER_CERT),
                    extraSignedAttrs = setOf(malformedAttribute),
                    encapsulatePlaintext = false,
                )
                val malformedBundle = SignatureBundle(mockMemberIdBundle(), invalidSignedData)

                val exception = assertThrows<SignatureException> {
                    malformedBundle.verify(plaintext, SERVICE_OID.id)
                }

                exception.message shouldBe "Metadata attribute is malformed"
                exception.cause shouldBe instanceOf<SignatureException>()
            }

            @Test
            fun `Service OID should match that of the signature metadata`() = runTest {
                val otherMetadata = SignatureMetadata(otherService, validityPeriod)
                val attribute = Attribute(
                    VeraOids.SIGNATURE_METADATA_ATTR,
                    DERSet(otherMetadata.encode()),
                )
                val signedData = SignedData.sign(
                    plaintext,
                    MEMBER_KEY_PAIR.private,
                    MEMBER_CERT,
                    setOf(MEMBER_CERT),
                    extraSignedAttrs = setOf(attribute),
                    encapsulatePlaintext = false,
                )
                val bundle = SignatureBundle(mockMemberIdBundle(), signedData)

                val exception = assertThrows<SignatureException> {
                    bundle.verify(plaintext, SERVICE_OID.id)
                }

                exception.message shouldBe
                    "Signature is bound to a different service (${otherService.id})"
            }

            @Test
            fun `Service OID in signature should match that of member id bundle`() = runTest {
                val mockMemberIdBundle = mockMemberIdBundle()
                val bundle = SignatureBundle(mockMemberIdBundle, validBundle.signedData)

                bundle.verify(plaintext, SERVICE_OID.id)

                argumentCaptor<ASN1ObjectIdentifier>().apply {
                    verify(mockMemberIdBundle).verify(capture(), any())

                    firstValue shouldBe SERVICE_OID
                }
            }
        }

        @Nested
        inner class ValidResult {
            @Test
            fun `Organisation name should be output`() = runTest {
                val bundle = SignatureBundle(mockMemberIdBundle(), validBundle.signedData)

                val result = bundle.verify(plaintext, SERVICE_OID.id)

                result.orgName shouldBe ORG_NAME
            }

            @Test
            fun `User name should be output if member is a user`() = runTest {
                val bundle = SignatureBundle(mockMemberIdBundle(), validBundle.signedData)

                val result = bundle.verify(plaintext, SERVICE_OID.id)

                result.userName shouldBe USER_NAME
            }

            @Test
            fun `User name should not be output if member is a bot`() = runTest {
                val memberIdBundleMock = mockMemberIdBundle(userName = null)
                val bundle = SignatureBundle(memberIdBundleMock, validBundle.signedData)

                val result = bundle.verify(plaintext, SERVICE_OID.id)

                result.userName shouldBe null
            }
        }

        private suspend fun mockMemberIdBundle(userName: String? = USER_NAME): MemberIdBundle {
            val memberIdBundleMock = mock<MemberIdBundle>()
            val member = Member(ORG_NAME, userName)
            whenever(memberIdBundleMock.verify(any(), any())).thenReturn(member)
            return memberIdBundleMock
        }
    }
}
