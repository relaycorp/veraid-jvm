package tech.relaycorp.veraid.utils

import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.SignerInfoGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import tech.relaycorp.veraid.utils.x509.Certificate
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZonedDateTime

internal fun issueStubCertificate(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    issuerCertificate: Certificate? = null,
    isCA: Boolean = false,
): Certificate {
    return Certificate.issue(
        "the subject for the stub cert",
        subjectPublicKey,
        issuerPrivateKey,
        ZonedDateTime.now().plusDays(1),
        isCA = isCA,
        issuerCertificate = issuerCertificate,
    )
}

internal fun PrivateKey.makeSignerInfoGenerator(
    certificate: X509CertificateHolder,
    algorithm: String = "SHA256WITHRSAANDMGF1",
): SignerInfoGenerator {
    val signerBuilder = JcaContentSignerBuilder(algorithm).setProvider(BC_PROVIDER)
    val contentSigner = signerBuilder.build(this)
    val digestProvider = JcaDigestCalculatorProviderBuilder().build()
    return JcaSignerInfoGeneratorBuilder(digestProvider).build(contentSigner, certificate)
}

internal fun CMSSignedDataGenerator.generateWithDetachedPlaintext(plaintext: ByteArray) =
    CMSSignedData(
        // Work around BC bug that keeps the plaintext encapsulated in the CMSSignedData
        // instance even if it's not encapsulated
        generate(CMSProcessableByteArray(plaintext), false).toASN1Structure(),
    )
