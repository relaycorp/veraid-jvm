package tech.relaycorp.veraid.utils.cms

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.beInstanceOf
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.veraid.pki.generateRSAKeyPair
import tech.relaycorp.veraid.utils.BC_PROVIDER
import tech.relaycorp.veraid.utils.Hash
import tech.relaycorp.veraid.utils.asn1.parseDer
import tech.relaycorp.veraid.utils.x509.Certificate
import java.security.MessageDigest
import java.time.ZonedDateTime

internal class SignedDataTest {
    companion object {
        val stubPlaintext = "The plaintext".toByteArray()
        val stubKeyPair = generateRSAKeyPair()
        val stubCertificate = Certificate.issue(
            "The Common Name",
            stubKeyPair.public,
            stubKeyPair.private,
            ZonedDateTime.now().plusDays(1),
        )
        val anotherStubCertificate = Certificate.issue(
            "Another",
            stubKeyPair.public,
            stubKeyPair.private,
            ZonedDateTime.now().plusDays(1),
        )
    }

    @Nested
    inner class Serialize {
        private val signedData =
            SignedData.sign(stubPlaintext, stubKeyPair.private, stubCertificate)

        @Test
        fun `Serialization should be DER-encoded`() {
            parseDer(signedData.serialize())
        }

        @Test
        fun `SignedData value should be wrapped in a ContentInfo value`() {
            ContentInfo.getInstance(parseDer(signedData.serialize()))
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Empty serialization should be refused`() {
            val invalidCMSSignedData = byteArrayOf()

            val exception = shouldThrow<SignedDataException> {
                SignedData.deserialize(invalidCMSSignedData)
            }

            exception.message shouldBe "Value cannot be empty"
        }

        @Test
        fun `Invalid DER values should be refused`() {
            val invalidCMSSignedData = "Not really DER-encoded".toByteArray()

            val exception = shouldThrow<SignedDataException> {
                SignedData.deserialize(invalidCMSSignedData)
            }

            exception.message shouldBe "Value is not DER-encoded"
        }

        @Test
        fun `ContentInfo wrapper should be required`() {
            val invalidCMSSignedData = ASN1Integer(10).encoded

            val exception = shouldThrow<SignedDataException> {
                SignedData.deserialize(invalidCMSSignedData)
            }

            exception.message shouldBe "SignedData value is not wrapped in ContentInfo"
        }

        @Test
        fun `ContentInfo wrapper should contain a valid SignedData value`() {
            val signedDataOid = ASN1ObjectIdentifier("1.2.840.113549.1.7.2")
            val invalidCMSSignedData = ContentInfo(signedDataOid, ASN1Integer(10))

            val exception = shouldThrow<SignedDataException> {
                SignedData.deserialize(invalidCMSSignedData.encoded)
            }

            exception.message shouldBe "ContentInfo wraps invalid SignedData value"
        }

        @Test
        fun `Valid SignedData values should be deserialized`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
            )
            val signedDataSerialized = signedData.serialize()

            val signedDataDeserialized = SignedData.deserialize(signedDataSerialized)

            signedDataDeserialized.bcSignedData.encoded shouldBe signedData.bcSignedData.encoded
        }
    }

    @Nested
    inner class Sign {
        @Test
        fun `SignedData version should be set to 1`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
            )

            signedData.bcSignedData.version shouldBe 1
        }

        @Nested
        inner class Plaintext {
            @Test
            fun `Plaintext should be encapsulated by default`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                )

                signedData.plaintext shouldBe stubPlaintext
            }

            @Test
            fun `Plaintext should not be encapsulated if requested`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                    encapsulatePlaintext = false,
                )

                signedData.plaintext shouldBe null
            }
        }

        @Nested
        inner class SignerInfo {
            @Test
            fun `There should only be one SignerInfo`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                )

                signedData.bcSignedData.signerInfos shouldHaveSize 1
            }

            @Test
            fun `SignerInfo version should be set to 1 when signed with a certificate`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                )

                val signerInfo = signedData.bcSignedData.signerInfos.first()
                signerInfo.version shouldBe 1
            }

            @Test
            fun `SignerIdentifier should be IssuerAndSerialNumber`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                )

                val signerInfo = signedData.bcSignedData.signerInfos.first()
                signerInfo.sid.issuer shouldBe stubCertificate.certificateHolder.issuer
                signerInfo.sid.serialNumber shouldBe stubCertificate.certificateHolder.serialNumber
            }

            @Test
            fun `Signature algorithm should be RSA-PSS`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                )

                val signerInfo = signedData.bcSignedData.signerInfos.first()
                signerInfo.encryptionAlgOID shouldBe PKCSObjectIdentifiers.id_RSASSA_PSS.id
            }

            @Nested
            inner class SignedAttributes {
                @Test
                fun `Signed attributes should be present`() {
                    val signedData = SignedData.sign(
                        stubPlaintext,
                        stubKeyPair.private,
                        stubCertificate,
                    )

                    signedData.signedAttrs!!.size() shouldBeGreaterThan 0
                }

                @Test
                fun `Content type attribute should be set to CMS Data`() {
                    val signedData = SignedData.sign(
                        stubPlaintext,
                        stubKeyPair.private,
                        stubCertificate,
                    )

                    val contentTypeAttrs =
                        signedData.signedAttrs!!.getAll(CMSAttributes.contentType)
                    contentTypeAttrs.size() shouldBe 1
                    val contentTypeAttr = contentTypeAttrs.get(0) as Attribute
                    contentTypeAttr.attributeValues.size shouldBe 1
                    contentTypeAttr.attributeValues[0] shouldBe CMSObjectIdentifiers.data
                }

                @Test
                fun `Plaintext digest should be present`() {
                    val signedData = SignedData.sign(
                        stubPlaintext,
                        stubKeyPair.private,
                        stubCertificate,
                    )

                    val digestAttrs = signedData.signedAttrs!!.getAll(
                        PKCSObjectIdentifiers.pkcs_9_at_messageDigest,
                    )
                    digestAttrs.size() shouldBe 1
                    val digestAttr = digestAttrs.get(0) as Attribute
                    digestAttr.attributeValues.size shouldBe 1
                    val digest = MessageDigest.getInstance("SHA-256").digest(stubPlaintext)
                    (digestAttr.attributeValues[0] as DEROctetString).octets shouldBe digest
                }

                @Test
                fun `Extra attributes should be honoured`() {
                    val attrOid = ASN1ObjectIdentifier("1.2.3.4.5")
                    val attrValueVector = ASN1EncodableVector(1)
                    attrValueVector.add(DERNull.INSTANCE)
                    val attrValue = DERSet(attrValueVector)
                    val attr = Attribute(attrOid, attrValue)
                    val signedData = SignedData.sign(
                        stubPlaintext,
                        stubKeyPair.private,
                        stubCertificate,
                        extraSignedAttrs = listOf(attr),
                    )

                    signedData.signedAttrs?.get(attrOid) shouldBe attr
                }
            }
        }

        @Nested
        inner class Certificates {
            @Test
            fun `Signer certificate should not be encapsulated by default`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                )

                signedData.signerCertificate shouldBe null
                signedData.certificates.size shouldBe 0
            }

            @Test
            fun `CA certificate chain should optionally be encapsulated`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                    setOf(stubCertificate, anotherStubCertificate),
                )

                signedData.certificates.size shouldBe 2
                signedData.certificates shouldContain anotherStubCertificate
            }
        }

        @Nested
        inner class Hashing {
            @Test
            fun `SHA-256 should be used by default`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                )

                assertHashingAlgoEquals(signedData, Hash.SHA_256)
            }

            @ParameterizedTest(name = "{0} should be honored if explicitly set")
            @EnumSource
            fun `Hashing algorithm should be customizable`(algorithm: Hash) {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                    hashingAlgorithm = algorithm,
                )

                assertHashingAlgoEquals(signedData, algorithm)
            }

            private fun assertHashingAlgoEquals(
                signedData: SignedData,
                expectedHashingAlgorithm: Hash,
            ) {
                val expectedHashingAlgoOID = HASHING_ALGORITHM_OIDS[expectedHashingAlgorithm]

                signedData.bcSignedData.digestAlgorithmIDs.size shouldBe 1
                signedData.bcSignedData.digestAlgorithmIDs.first().algorithm shouldBe
                    expectedHashingAlgoOID

                val signerInfo = signedData.bcSignedData.signerInfos.first()
                signerInfo.digestAlgorithmID.algorithm shouldBe expectedHashingAlgoOID
            }
        }
    }

    @Nested
    inner class Verify {
        @Test
        fun `Invalid signature with encapsulated plaintext should be refused`() {
            // Swap the SignerInfo collection from two different CMS SignedData values

            val signedData1 = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
            )

            val signedData2 = SignedData.sign(
                byteArrayOf(0xde.toByte(), *stubPlaintext),
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
            )

            val invalidBCSignedData = CMSSignedData.replaceSigners(
                signedData1.bcSignedData,
                signedData2.bcSignedData.signerInfos,
            )
            val invalidSignedData = SignedData.deserialize(invalidBCSignedData.encoded)

            val exception = shouldThrow<SignedDataException> {
                invalidSignedData.verify()
            }

            exception.message shouldBe "Could not verify signature"
            exception.cause should beInstanceOf<CMSException>()
        }

        @Test
        fun `Invalid signature without encapsulated plaintext should be refused`() {
            // Swap the SignerInfo collection from two different CMS SignedData values

            val signedData1 = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
                encapsulatePlaintext = false,
            )

            val signedData2 = SignedData.sign(
                byteArrayOf(0xde.toByte(), *stubPlaintext),
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
                encapsulatePlaintext = false,
            )

            val invalidBCSignedData = CMSSignedData.replaceSigners(
                signedData1.bcSignedData,
                signedData2.bcSignedData.signerInfos,
            )
            val invalidSignedData = SignedData.deserialize(invalidBCSignedData.encoded)

            val exception = shouldThrow<SignedDataException> {
                invalidSignedData.verify(
                    stubPlaintext,
                )
            }

            exception.message shouldBe "Could not verify signature"
            exception.cause should beInstanceOf<CMSException>()
        }

        @Test
        fun `Signature with non-matching asymmetric keys should be refused`() {
            // Do the verification with a different key pair

            val anotherKeyPair = generateRSAKeyPair()
            val signedData = SignedData.sign(
                stubPlaintext,
                anotherKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
            )

            val exception = shouldThrow<SignedDataException> {
                signedData.verify()
            }

            exception.message shouldBe "Invalid signature"
            exception.cause shouldBe null
        }

        @Test
        fun `Signed content should be encapsulated if no specific plaintext is expected`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
                encapsulatePlaintext = false,
            )

            val exception = shouldThrow<SignedDataException> { signedData.verify() }

            exception.message shouldBe "Plaintext should be encapsulated or explicitly set"
        }

        @Test
        fun `Expected plaintext should be refused if one is already encapsulated`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
            )

            val exception = shouldThrow<SignedDataException> {
                signedData.verify(stubPlaintext)
            }

            exception.message shouldBe
                "No specific plaintext should be expected because one is already encapsulated"
        }

        @Test
        fun `Valid signature with encapsulated plaintext should be accepted`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
            )

            cmsSignedData.verify()
        }

        @Test
        fun `Valid signature without encapsulated plaintext should be accepted`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
                encapsulatePlaintext = false,
            )

            cmsSignedData.verify(stubPlaintext)
        }

        @Test
        fun `Signer certificate should be encapsulated`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
            )

            val exception = shouldThrow<SignedDataException> { signedData.verify() }

            exception.message shouldBe "Signer certificate should be encapsulated"
        }

        @Test
        fun `Valid signature with encapsulated signer certificate should succeed`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                encapsulatedCertificates = setOf(stubCertificate),
            )

            cmsSignedData.verify()
        }
    }

    @Nested
    inner class Plaintext {
        @Test
        fun `Plaintext should be null if not encapsulated`() {
            val signedDataGenerator = CMSSignedDataGenerator()

            val signerBuilder =
                JcaContentSignerBuilder("SHA256WITHRSAANDMGF1").setProvider(BC_PROVIDER)
            val contentSigner: ContentSigner = signerBuilder.build(stubKeyPair.private)
            val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
                JcaDigestCalculatorProviderBuilder()
                    .build(),
            ).build(contentSigner, stubCertificate.certificateHolder)
            signedDataGenerator.addSignerInfoGenerator(
                signerInfoGenerator,
            )

            val certs = JcaCertStore(listOf(stubCertificate.certificateHolder))
            signedDataGenerator.addCertificates(certs)

            val plaintextCms: CMSTypedData = CMSProcessableByteArray(stubPlaintext)
            val bcSignedData = signedDataGenerator.generate(plaintextCms, false)
            val signedData = SignedData.deserialize(bcSignedData.encoded)

            signedData.plaintext shouldBe null
        }

        @Test
        fun `Plaintext should be output if encapsulated`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
            )

            cmsSignedData.plaintext shouldBe stubPlaintext
        }
    }

    @Nested
    inner class SignerCertificate {
        @Test
        fun `An empty SignerInfo collection should be refused`() {
            val signedData = generateSignedDataWithoutSigners()

            val exception = shouldThrow<SignedDataException> {
                signedData.signerCertificate
            }

            exception.message shouldBe "SignedData should contain exactly one SignerInfo"
        }

        @Test
        fun `A SignerInfo collection with more than one item should be refused`() {
            val signedData = generateSignedDataWithMultipleSigners()

            val exception = shouldThrow<SignedDataException> {
                signedData.signerCertificate
            }

            exception.message shouldBe "SignedData should contain exactly one SignerInfo"
        }

        @Test
        fun `Certificate of signer may not be encapsulated`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
            )

            cmsSignedData.signerCertificate shouldBe null
        }

        @Test
        fun `Signer certificate should be output if present`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
            )

            cmsSignedData.signerCertificate shouldBe stubCertificate
        }
    }

    @Nested
    inner class SignedAttrs {
        @Test
        fun `An empty SignerInfo collection should result in null`() {
            val signedData = generateSignedDataWithoutSigners()

            signedData.signedAttrs shouldBe null
        }

        @Test
        fun `Multiple SignerInfos should result in null`() {
            val signedData = generateSignedDataWithMultipleSigners()

            signedData.signedAttrs shouldBe null
        }

        @Test
        fun `Signed attributes should be output`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
            )

            signedData.signedAttrs shouldNotBe null
            signedData.signedAttrs!!.size() shouldBeGreaterThan 0
            signedData.signedAttrs.getAll(CMSAttributes.contentType).size() shouldBe 1
        }
    }

    @Nested
    inner class Certificates {
        @Test
        fun `No certificates may be encapsulated`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
            )

            cmsSignedData.certificates.size shouldBe 0
        }

        @Test
        fun `One certificate may be encapsulated`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                encapsulatedCertificates = setOf(stubCertificate),
            )

            cmsSignedData.certificates shouldContain stubCertificate
        }

        @Test
        fun `Multiple certificates may be encapsulated`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                encapsulatedCertificates = setOf(stubCertificate, anotherStubCertificate),
            )

            cmsSignedData.certificates shouldContain stubCertificate
            cmsSignedData.certificates shouldContain anotherStubCertificate
        }
    }

    private fun generateSignedDataWithoutSigners(): SignedData {
        val signedDataGenerator = CMSSignedDataGenerator()
        val plaintextCms: CMSTypedData = CMSProcessableByteArray(stubPlaintext)
        val bcSignedData = signedDataGenerator.generate(plaintextCms, true)
        return SignedData(bcSignedData)
    }

    private fun generateSignedDataWithMultipleSigners(): SignedData {
        val signedDataGenerator = CMSSignedDataGenerator()

        val signerBuilder =
            JcaContentSignerBuilder("SHA256WITHRSAANDMGF1").setProvider(BC_PROVIDER)
        val contentSigner: ContentSigner = signerBuilder.build(stubKeyPair.private)
        val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
            JcaDigestCalculatorProviderBuilder()
                .build(),
        ).build(contentSigner, stubCertificate.certificateHolder)
        // Add the same SignerInfo twice
        signedDataGenerator.addSignerInfoGenerator(
            signerInfoGenerator,
        )
        signedDataGenerator.addSignerInfoGenerator(
            signerInfoGenerator,
        )

        val bcSignedData = signedDataGenerator.generate(
            CMSProcessableByteArray(stubPlaintext),
            true,
        )
        return SignedData(bcSignedData)
    }
}
