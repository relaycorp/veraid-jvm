package tech.relaycorp.veraid.pki

import io.kotest.matchers.date.shouldBeBefore
import io.kotest.matchers.date.shouldNotBeBefore
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.ORG_KEY_PAIR
import tech.relaycorp.veraid.ORG_NAME
import tech.relaycorp.veraid.utils.BC_PROVIDER
import java.math.BigInteger
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit

class OrgCertificateTest {
    @Nested
    inner class SelfIssue {
        private val expiryDate = ZonedDateTime.now().plusMinutes(60).truncatedTo(ChronoUnit.SECONDS)

        @Test
        fun `Name should be used as Common Name`() {
            val cert = OrgCertificate.selfIssue(ORG_NAME, ORG_KEY_PAIR, expiryDate)

            cert.commonName shouldBe ORG_NAME
            cert.issuerCommonName shouldBe ORG_NAME
        }

        @Test
        fun `Subject public key should be honoured`() {
            val cert = OrgCertificate.selfIssue(ORG_NAME, ORG_KEY_PAIR, expiryDate)

            cert.subjectPublicKey shouldBe ORG_KEY_PAIR.public
        }

        @Test
        fun `Certificate should be signed with private key`() {
            val cert = OrgCertificate.selfIssue(ORG_NAME, ORG_KEY_PAIR, expiryDate)

            val verifierProvider = JcaContentVerifierProviderBuilder()
                .setProvider(BC_PROVIDER)
                .build(ORG_KEY_PAIR.public)
            cert.certificateHolder.isSignatureValid(verifierProvider) shouldBe true
        }

        @Test
        fun `Expiry date should match specified one`() {
            val cert = OrgCertificate.selfIssue(ORG_NAME, ORG_KEY_PAIR, expiryDate)

            cert.expiryDate shouldBe expiryDate
        }

        @Nested
        inner class StartDate {
            @Test
            fun `should default to now`() {
                val beforeIssuance = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS)

                val cert = OrgCertificate.selfIssue(ORG_NAME, ORG_KEY_PAIR, expiryDate)

                val afterIssuance = ZonedDateTime.now()
                cert.startDate shouldNotBeBefore beforeIssuance
                cert.startDate shouldBeBefore afterIssuance
            }

            @Test
            fun `should match explicit date if set`() {
                val startDate = expiryDate.minusSeconds(2)

                val cert = OrgCertificate.selfIssue(ORG_NAME, ORG_KEY_PAIR, expiryDate, startDate)

                cert.startDate shouldBe startDate
            }
        }

        @Nested
        inner class BasicConstraintsExtension {
            @Test
            fun `Subject should be a CA`() {
                val cert = OrgCertificate.selfIssue(ORG_NAME, ORG_KEY_PAIR, expiryDate)

                cert.isCA shouldBe true
            }

            @Test
            fun `Path length should be zero`() {
                val cert = OrgCertificate.selfIssue(ORG_NAME, ORG_KEY_PAIR, expiryDate)

                val basicConstraints =
                    BasicConstraints.fromExtensions(cert.certificateHolder.extensions)
                basicConstraints.pathLenConstraint shouldBe BigInteger.ZERO
            }
        }
    }
}
