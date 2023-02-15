package tech.relaycorp.vera.pki

import io.kotest.matchers.date.shouldBeBefore
import io.kotest.matchers.date.shouldNotBeBefore
import io.kotest.matchers.shouldBe
import java.math.BigInteger
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.vera.ORG_KEY_PAIR
import tech.relaycorp.vera.ORG_NAME
import tech.relaycorp.vera.utils.BC_PROVIDER
import tech.relaycorp.vera.utils.x509.Certificate

class OrganisationCATest {
    @Nested
    inner class SelfIssueOrganisationCertificate {
        private val expiryDate = ZonedDateTime.now().plusMinutes(60).truncatedTo(ChronoUnit.SECONDS)

        @Test
        fun `Name should be used as Common Name`() {
            val certSerialised = ORG_KEY_PAIR.selfIssueOrgCertificate(ORG_NAME, expiryDate)

            val cert = Certificate.deserialize(certSerialised)
            cert.commonName shouldBe ORG_NAME
            cert.issuerCommonName shouldBe ORG_NAME
        }

        @Test
        fun `Subject public key should be honoured`() {
            val certSerialised = ORG_KEY_PAIR.selfIssueOrgCertificate(ORG_NAME, expiryDate)

            val cert = Certificate.deserialize(certSerialised)
            cert.subjectPublicKey shouldBe ORG_KEY_PAIR.public
        }

        @Test
        fun `Certificate should be signed with private key`() {
            val certSerialised = ORG_KEY_PAIR.selfIssueOrgCertificate(ORG_NAME, expiryDate)

            val cert = Certificate.deserialize(certSerialised)
            val verifierProvider = JcaContentVerifierProviderBuilder()
                .setProvider(BC_PROVIDER)
                .build(ORG_KEY_PAIR.public)
            cert.certificateHolder.isSignatureValid(verifierProvider) shouldBe true
        }

        @Test
        fun `Expiry date should match specified one`() {
            val certSerialised = ORG_KEY_PAIR.selfIssueOrgCertificate(ORG_NAME, expiryDate)

            val cert = Certificate.deserialize(certSerialised)
            cert.expiryDate shouldBe expiryDate
        }

        @Nested
        inner class StartDate {
            @Test
            fun `should default to now`() {
                val beforeIssuance = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS)

                val certSerialised = ORG_KEY_PAIR.selfIssueOrgCertificate(ORG_NAME, expiryDate)

                val afterIssuance = ZonedDateTime.now()
                val cert = Certificate.deserialize(certSerialised)
                cert.startDate shouldNotBeBefore beforeIssuance
                cert.startDate shouldBeBefore afterIssuance
            }

            @Test
            fun `should match explicit date if set`() {
                val startDate = expiryDate.minusSeconds(2)

                val certSerialised =
                    ORG_KEY_PAIR.selfIssueOrgCertificate(ORG_NAME, expiryDate, startDate)

                val cert = Certificate.deserialize(certSerialised)
                cert.startDate shouldBe startDate
            }
        }

        @Nested
        inner class BasicConstraintsExtension {
            @Test
            fun `Subject should be a CA`() {
                val startDate = expiryDate.minusSeconds(2)

                val certSerialised =
                    ORG_KEY_PAIR.selfIssueOrgCertificate(ORG_NAME, expiryDate, startDate)

                val cert = Certificate.deserialize(certSerialised)
                cert.isCA shouldBe true
            }

            @Test
            fun `Path length should be zero`() {
                val startDate = expiryDate.minusSeconds(2)

                val certSerialised =
                    ORG_KEY_PAIR.selfIssueOrgCertificate(ORG_NAME, expiryDate, startDate)

                val cert = Certificate.deserialize(certSerialised)
                val basicConstraints =
                    BasicConstraints.fromExtensions(cert.certificateHolder.extensions)
                basicConstraints.pathLenConstraint shouldBe BigInteger.ZERO
            }
        }
    }
}
