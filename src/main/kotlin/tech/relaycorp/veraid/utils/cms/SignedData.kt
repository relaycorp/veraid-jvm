package tech.relaycorp.veraid.utils.cms

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.selector.X509CertificateHolderSelector
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.CollectionStore
import org.bouncycastle.util.Selector
import tech.relaycorp.veraid.utils.BC_PROVIDER
import tech.relaycorp.veraid.utils.Hash
import tech.relaycorp.veraid.utils.x509.Certificate
import java.io.IOException
import java.security.PrivateKey

internal class SignedData(val bcSignedData: CMSSignedData) {
    /**
     * The signed plaintext, if it was encapsulated.
     */
    val plaintext: ByteArray? by lazy { bcSignedData.signedContent?.content as ByteArray? }

    /**
     * The signer's certificate, if it was encapsulated.
     */
    val signerCertificate: Certificate? by lazy {
        val signerInfo = getSignerInfo(bcSignedData)

        // We shouldn't have to force this type cast but this is the only way I could get the code to work and, based on
        // what I found online, that's what others have had to do as well
        @Suppress("UNCHECKED_CAST")
        val signerCertSelector = X509CertificateHolderSelector(
            signerInfo.sid.issuer,
            signerInfo.sid.serialNumber,
        ) as Selector<X509CertificateHolder>

        val signerCertMatches = bcSignedData.certificates.getMatches(signerCertSelector)
        try {
            Certificate(signerCertMatches.first())
        } catch (_: NoSuchElementException) {
            null
        }
    }

    /**
     * Set of encapsulated certificates.
     */
    val certificates: Set<Certificate> by lazy {
        (bcSignedData.certificates as CollectionStore).map { Certificate(it) }.toSet()
    }

    fun serialize(): ByteArray = bcSignedData.encoded

    /**
     * Verify signature.
     *
     * @param expectedPlaintext The plaintext to be verified if none is encapsulated
     */
    @Throws(SignedDataException::class)
    fun verify(expectedPlaintext: ByteArray? = null) {
        if (plaintext != null && expectedPlaintext != null) {
            throw SignedDataException(
                "No specific plaintext should be expected because one is already encapsulated",
            )
        }
        val signedPlaintext = plaintext
            ?: expectedPlaintext
            ?: throw SignedDataException("Plaintext should be encapsulated or explicitly set")

        if (signerCertificate == null) {
            throw SignedDataException("Signer certificate should be encapsulated")
        }
        val signedData = CMSSignedData(
            CMSProcessableByteArray(signedPlaintext),
            bcSignedData.toASN1Structure(),
        )
        val signerInfo = getSignerInfo(signedData)
        val verifierBuilder = JcaSimpleSignerInfoVerifierBuilder().setProvider(BC_PROVIDER)
        val verifier = verifierBuilder.build(signerCertificate!!.certificateHolder)
        val isValid = try {
            signerInfo.verify(verifier)
        } catch (exc: CMSException) {
            throw SignedDataException("Could not verify signature", exc)
        }
        if (!isValid) {
            throw SignedDataException("Invalid signature")
        }
    }

    companion object {
        private val signatureAlgorithmMap = mapOf(
            Hash.SHA_256 to "SHA256WITHRSAANDMGF1",
            Hash.SHA_384 to "SHA384WITHRSAANDMGF1",
            Hash.SHA_512 to "SHA512WITHRSAANDMGF1",
        )

        /**
         * Generate SignedData value with a SignerInfo using an IssuerAndSerialNumber id.
         */
        @JvmStatic
        fun sign(
            plaintext: ByteArray,
            signerPrivateKey: PrivateKey,
            signerCertificate: Certificate,
            encapsulatedCertificates: Set<Certificate> = setOf(),
            hashingAlgorithm: Hash? = null,
            encapsulatePlaintext: Boolean = true,
        ): SignedData {
            val contentSigner = makeContentSigner(signerPrivateKey, hashingAlgorithm)
            val signerInfoGenerator = makeSignerInfoGeneratorBuilder().build(
                contentSigner,
                signerCertificate.certificateHolder,
            )
            val signedDataGenerator = CMSSignedDataGenerator()
            signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator)
            val certs = JcaCertStore(encapsulatedCertificates.map { it.certificateHolder })
            signedDataGenerator.addCertificates(certs)
            val plaintextCms: CMSTypedData = CMSProcessableByteArray(plaintext)
            val bcSignedData = signedDataGenerator.generate(
                plaintextCms,
                encapsulatePlaintext,
            )
            return SignedData(
                // Work around BC bug that keeps the plaintext encapsulated in the CMSSignedData
                // instance even if it's not encapsulated
                if (encapsulatePlaintext) {
                    bcSignedData
                } else {
                    CMSSignedData(bcSignedData.toASN1Structure())
                },
            )
        }

        private fun makeSignerInfoGeneratorBuilder() = JcaSignerInfoGeneratorBuilder(
            JcaDigestCalculatorProviderBuilder().build(),
        )

        private fun makeContentSigner(
            signerPrivateKey: PrivateKey,
            hashingAlgorithm: Hash?,
        ): ContentSigner {
            val algorithm = hashingAlgorithm ?: Hash.SHA_256
            val signerBuilder =
                JcaContentSignerBuilder(signatureAlgorithmMap[algorithm]).setProvider(BC_PROVIDER)
            return signerBuilder.build(signerPrivateKey)
        }

        @JvmStatic
        fun deserialize(serialization: ByteArray): SignedData {
            if (serialization.isEmpty()) {
                throw SignedDataException("Value cannot be empty")
            }
            val asn1Stream = ASN1InputStream(serialization)
            val asn1Sequence = try {
                asn1Stream.readObject()
            } catch (_: IOException) {
                throw SignedDataException("Value is not DER-encoded")
            }
            val contentInfo = try {
                ContentInfo.getInstance(asn1Sequence)
            } catch (_: IllegalArgumentException) {
                throw SignedDataException("SignedData value is not wrapped in ContentInfo")
            }
            val bcSignedData = try {
                CMSSignedData(contentInfo)
            } catch (_: CMSException) {
                throw SignedDataException("ContentInfo wraps invalid SignedData value")
            }
            return SignedData(bcSignedData)
        }

        private fun getSignerInfo(bcSignedData: CMSSignedData): SignerInformation {
            val signersCount = bcSignedData.signerInfos.size()
            if (signersCount != 1) {
                throw SignedDataException(
                    "SignedData should contain exactly one SignerInfo (got $signersCount)",
                )
            }
            return bcSignedData.signerInfos.first()
        }
    }
}
