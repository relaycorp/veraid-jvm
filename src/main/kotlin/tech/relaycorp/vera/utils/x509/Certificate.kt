package tech.relaycorp.vera.utils.x509

import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertPathBuilder
import java.security.cert.CertPathBuilderException
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXCertPathBuilderResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.Date
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DERBMPString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import tech.relaycorp.vera.utils.BC_PROVIDER
import tech.relaycorp.vera.utils.generateRandomBigInteger
import tech.relaycorp.vera.utils.getSHA256Digest

/**
 * Certificate.
 *
 * @param certificateHolder Bouncy Castle representation of the X.509 certificate
 */
public open class Certificate internal constructor(
    internal val certificateHolder: X509CertificateHolder,
) {
    internal companion object {
        private val bcToJavaCertificateConverter: JcaX509CertificateConverter =
            JcaX509CertificateConverter().setProvider(BC_PROVIDER)

        /**
         * Issue a new certificate.
         */
        @Throws(CertificateException::class)
        fun issue(
            subjectCommonName: String,
            subjectPublicKey: PublicKey,
            issuerPrivateKey: PrivateKey,
            validityEndDate: ZonedDateTime,
            issuerCertificate: Certificate? = null,
            isCA: Boolean = false,
            pathLenConstraint: Int = 0,
            validityStartDate: ZonedDateTime = ZonedDateTime.now()
        ): Certificate {
            val expiryDate = if (issuerCertificate != null) minOf(
                issuerCertificate.expiryDate,
                validityEndDate
            ) else validityEndDate

            if (validityStartDate >= expiryDate) {
                throw CertificateException("The end date must be later than the start date")
            }
            if (issuerCertificate != null && !issuerCertificate.isCA) {
                throw CertificateException("Issuer certificate should be marked as CA")
            }

            val subjectDistinguishedName = buildDistinguishedName(subjectCommonName)
            val issuerDistinguishedName = if (issuerCertificate != null)
                issuerCertificate.certificateHolder.subject
            else
                subjectDistinguishedName
            val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(subjectPublicKey.encoded)
            val builder = X509v3CertificateBuilder(
                issuerDistinguishedName,
                generateRandomBigInteger(),
                Date.from(validityStartDate.toInstant()),
                Date.from(expiryDate.toInstant()),
                subjectDistinguishedName,
                subjectPublicKeyInfo
            )

            val basicConstraints = BasicConstraintsExtension(isCA, pathLenConstraint)
            builder.addExtension(Extension.basicConstraints, true, basicConstraints)

            val subjectPublicKeyDigest = getSHA256Digest(subjectPublicKeyInfo.encoded)
            val subjectSKI = SubjectKeyIdentifier(subjectPublicKeyDigest)
            builder.addExtension(Extension.subjectKeyIdentifier, false, subjectSKI)

            var issuerSKI = subjectSKI
            if (issuerCertificate != null) {
                issuerSKI =
                    SubjectKeyIdentifier.fromExtensions(
                        issuerCertificate.certificateHolder.extensions
                    ) ?: throw CertificateException(
                        "Issuer must have the SubjectKeyIdentifier extension"
                    )
            }
            val aki = AuthorityKeyIdentifier(issuerSKI.keyIdentifier)
            builder.addExtension(Extension.authorityKeyIdentifier, false, aki)

            val signer = JcaContentSignerBuilder("SHA256WITHRSAANDMGF1")
                .setProvider(BC_PROVIDER)
                .build(issuerPrivateKey)
            val certificateHolder = builder.build(signer)
            return Certificate(certificateHolder)
        }

        @Throws(CertificateException::class)
        private fun buildDistinguishedName(commonName: String): X500Name {
            val builder = X500NameBuilder(BCStyle.INSTANCE)
            builder.addRDN(BCStyle.CN, DERBMPString(commonName))
            return builder.build()
        }

        /**
         * Decode certificate.
         */
        @Throws(CertificateException::class)
        fun decode(certificateEncoded: ASN1Encodable): Certificate {
            val bcCertificate = try {
                org.bouncycastle.asn1.x509.Certificate.getInstance(certificateEncoded)
            } catch (exc: IllegalArgumentException) {
                throw CertificateException("ASN.1 value is not an X.509 v3 certificate", exc)
            }
            val certificateHolder = X509CertificateHolder(bcCertificate)
            return Certificate(certificateHolder)
        }

        /**
         * Deserialise certificate,
         *
         * @param certificateSerialized The DER-encoded serialisation of the certificate
         */
        @Throws(CertificateException::class)
        fun deserialise(certificateSerialized: ByteArray): Certificate {
            val certificateHolder = try {
                X509CertificateHolder(certificateSerialized)
            } catch (exc: IOException) {
                throw CertificateException(
                    "Value should be a DER-encoded, X.509 v3 certificate",
                    exc
                )
            }
            return Certificate(certificateHolder)
        }

        private fun getCommonName(x500Name: X500Name): String {
            val commonNames = x500Name.getRDNs(BCStyle.CN)
            return commonNames.first().first.value.toString()
        }
    }

    /**
     * Return the Common Name of the subject
     */
    public val commonName: String
        get() = getCommonName(certificateHolder.subject)

    /**
     * The public key of the subject.
     */
    public val subjectPublicKey: PublicKey
        get() = convertCertToJava(this).publicKey

    /**
     * Return the Common Name of the issuer
     */
    public val issuerCommonName: String
        get() = getCommonName(certificateHolder.issuer)

    /**
     * The start date of the certificate.
     */
    public val startDate: ZonedDateTime
        get() = dateToZonedDateTime(certificateHolder.notBefore)

    /**
     * The expiry date of the certificate.
     */
    public val expiryDate: ZonedDateTime
        get() = dateToZonedDateTime(certificateHolder.notAfter)

    private val basicConstraints: BasicConstraints? by lazy {
        BasicConstraints.fromExtensions(certificateHolder.extensions)
    }

    /**
     * Report whether the subject is a CA.
     */
    internal val isCA: Boolean by lazy { basicConstraints?.isCA == true }

    /**
     * Report whether this certificate equals another.
     */
    override fun equals(other: Any?): Boolean {
        if (other?.javaClass != this.javaClass) {
            return false
        }
        other as Certificate
        return certificateHolder == other.certificateHolder
    }

    /**
     * Return the hash code of the certificate.
     */
    override fun hashCode(): Int {
        return certificateHolder.hashCode()
    }

    /**
     * Return the DER serialisation of the certificate.
     */
    public fun serialise(): ByteArray {
        return certificateHolder.encoded
    }

    /**
     * Report whether [potentialIssuer]'s Distinguished Name matches that of the issuer
     * of the current certificate.
     *
     * This doesn't check that [potentialIssuer] actually signed the current certificate --
     * hence the "likely".
     */
    internal fun isLikelyIssuer(potentialIssuer: Certificate) =
        certificateHolder.issuer == potentialIssuer.certificateHolder.subject

    /**
     * Validate the certificate.
     *
     * @throws CertificateException If the certificate is invalid
     */
    @Throws(CertificateException::class)
    internal fun validate() {
        validateValidityPeriod()
        validateCommonNamePresence()
    }

    private fun validateValidityPeriod() {
        val now = ZonedDateTime.now()
        if (now < startDate) {
            throw CertificateException("Certificate is not yet valid")
        }
        if (expiryDate < now) {
            throw CertificateException("Certificate already expired")
        }
    }

    private fun validateCommonNamePresence() {
        if (certificateHolder.subject.getRDNs(BCStyle.CN).isEmpty()) {
            throw CertificateException("Subject should have a Common Name")
        }
    }

    /**
     * Get the certification path (aka certificate chain) between the current certificate and
     * one of the `trustedCAs`.
     *
     * @throws CertificateException if no path could be found
     */
    @Throws(CertificateException::class)
    internal fun getCertificationPath(
        intermediateCAs: Collection<Certificate>,
        trustedCAs: Collection<Certificate>
    ): List<Certificate> {
        val pathBuilderResult = try {
            buildPath(intermediateCAs, trustedCAs)
        } catch (exc: CertPathBuilderException) {
            throw CertificateException("No certification path could be found", exc)
        }

        // Convert the Java certificates in the path back to Bouncy Castle instances
        val bcCertPath = pathBuilderResult.certPath.certificates.map {
            // It's insane we have to serialize + deserialize, but I couldn't find any other way
            // to convert a Java certificate to BouncyCastle
            X509CertificateHolder(it.encoded)
        }

        // Convert the BC certificates back to the original Certificate instances.
        val cAs = bcCertPath.slice(1..bcCertPath.lastIndex).map { copy ->
            intermediateCAs.single { original -> copy == original.certificateHolder }
        }.toMutableList()

        // Include the root certificate unless this is a self-signed certificate:
        val bcRootCACert = X509CertificateHolder(pathBuilderResult.trustAnchor.trustedCert.encoded)
        if (bcRootCACert != this.certificateHolder) {
            val rootCACert = trustedCAs.single { it.certificateHolder == bcRootCACert }
            cAs.add(rootCACert)
        }

        return listOf(this, *cAs.toTypedArray())
    }

    @Throws(CertPathBuilderException::class)
    private fun buildPath(
        intermediateCAs: Collection<Certificate>,
        trustedCAs: Collection<Certificate>
    ): PKIXCertPathBuilderResult {
        // We have to start by converting all BC certificates to Java certificates because we
        // can't do this with BouncyCastle:
        // https://stackoverflow.com/q/63020771/129437
        val javaEndEntityCert = convertCertToJava(this)
        val javaIntermediateCACerts = intermediateCAs.map(::convertCertToJava)
        val javaTrustedCACerts = trustedCAs.map(::convertCertToJava)

        val trustAnchors = javaTrustedCACerts.map { TrustAnchor(it, null) }.toSet()

        val intermediateCertStore = CertStore.getInstance(
            "Collection",
            CollectionCertStoreParameters(javaIntermediateCACerts),
            BC_PROVIDER // Use BC for performance reasons
        )

        val endEntitySelector = X509CertSelector()
        endEntitySelector.certificate = javaEndEntityCert

        val parameters: PKIXParameters = try {
            PKIXBuilderParameters(trustAnchors, endEntitySelector)
        } catch (exc: InvalidAlgorithmParameterException) {
            throw CertificateException(
                "Failed to initialize path builder; set of trusted CAs might be empty",
                exc
            )
        }
        parameters.isRevocationEnabled = false
        parameters.addCertStore(intermediateCertStore)

        val pathBuilder: CertPathBuilder = CertPathBuilder.getInstance(
            "PKIX",
            BC_PROVIDER // Use BC for performance reasons
        )
        return pathBuilder.build(parameters) as PKIXCertPathBuilderResult
    }

    private fun convertCertToJava(certificate: Certificate) =
        bcToJavaCertificateConverter.getCertificate(certificate.certificateHolder)

    private fun dateToZonedDateTime(date: Date) = date.toInstant().atZone(
        ZoneId.systemDefault()
    )
}
