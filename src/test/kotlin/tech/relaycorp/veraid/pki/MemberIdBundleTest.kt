package tech.relaycorp.veraid.pki

import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.doThrow
import com.nhaarman.mockitokotlin2.eq
import com.nhaarman.mockitokotlin2.spy
import com.nhaarman.mockitokotlin2.verify
import com.nhaarman.mockitokotlin2.whenever
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.beInstanceOf
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Set
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.MEMBER_CERT
import tech.relaycorp.veraid.MEMBER_KEY_PAIR
import tech.relaycorp.veraid.ORG_CERT
import tech.relaycorp.veraid.ORG_KEY_PAIR
import tech.relaycorp.veraid.ORG_NAME
import tech.relaycorp.veraid.SERVICE_OID
import tech.relaycorp.veraid.USER_NAME
import tech.relaycorp.veraid.dns.DnsException
import tech.relaycorp.veraid.dns.InvalidChainException
import tech.relaycorp.veraid.dns.RECORD
import tech.relaycorp.veraid.dns.VeraDnssecChain
import tech.relaycorp.veraid.dns.makeResponse
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
import tech.relaycorp.veraid.utils.x509.Certificate
import tech.relaycorp.veraid.utils.x509.CertificateException
import java.math.BigInteger

class MemberIdBundleTest {
    private val response = RECORD.makeResponse()
    private val veraDnssecChain = VeraDnssecChain(ORG_NAME, listOf(response))

    @Nested
    inner class Serialise {
        private val bundle = MemberIdBundle(veraDnssecChain, ORG_CERT, MEMBER_CERT)

        @Test
        fun `Version should be 0`() {
            val serialisation = bundle.serialise()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialisation)
            val item = ASN1Integer.getInstance(sequence.first(), false)
            item.value shouldBe BigInteger.ZERO
        }

        @Test
        fun `DNSSEC chain should be included`() {
            val serialisation = bundle.serialise()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialisation)
            val item = ASN1Set.getInstance(sequence[1], false)
            val chainDecoded = VeraDnssecChain.decode(ORG_NAME, item)
            chainDecoded.responses.map { it.toWire() } shouldContain response.toWire()
        }

        @Test
        fun `Organisation certificate should be included`() {
            val serialisation = bundle.serialise()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialisation)

            Certificate.decode(sequence[2]).certificateHolder shouldBe
                ORG_CERT.certificateHolder
        }

        @Test
        fun `Member certificate should be included`() {
            val serialisation = bundle.serialise()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialisation)

            Certificate.decode(sequence[3]).certificateHolder shouldBe
                MEMBER_CERT.certificateHolder
        }
    }

    @Nested
    inner class Verify {
        @Nested
        inner class CertificateChain {
            @Test
            fun `Member certificate should be issued by organisation certificate`() = runTest {
                val otherOrgCert = OrgCertificate.selfIssue(
                    ORG_NAME,
                    generateRSAKeyPair(),
                    ORG_CERT.validityPeriod.endInclusive,
                )
                val bundle = MemberIdBundle(veraDnssecChain, otherOrgCert, MEMBER_CERT)

                val exception = shouldThrow<PkiException> {
                    bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)
                }

                exception.message shouldBe "Member certificate was not issued by organisation"
                exception.cause should beInstanceOf<CertificateException>()
            }

            @Test
            fun `Certificates should overlap with specified period`() = runTest {
                val bundle = MemberIdBundle(veraDnssecChain, ORG_CERT, MEMBER_CERT)
                val start = ORG_CERT.validityPeriod.endInclusive.plusSeconds(1)
                val period = start..start.plusSeconds(1)

                val exception = shouldThrow<PkiException> {
                    bundle.verify(SERVICE_OID, period)
                }

                exception.message shouldBe
                    "Validity period of certificate chain does not overlap with required period"
            }
        }

        @Nested
        inner class UserName {
            private val errorMessage =
                "User name should not contain at signs or whitespace other than simple spaces"

            @Test
            fun `should not contain at signs`() = runTest {
                val memberCert = issueInvalidMemberCertificate("@$USER_NAME")
                val bundle = MemberIdBundle(veraDnssecChain, ORG_CERT, memberCert)

                val exception = shouldThrow<PkiException> {
                    bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)
                }

                exception.message shouldBe errorMessage
            }

            @Test
            fun `should not contain tabs`() = runTest {
                val memberCert = issueInvalidMemberCertificate("\t$USER_NAME")
                val bundle = MemberIdBundle(veraDnssecChain, ORG_CERT, memberCert)

                val exception = shouldThrow<PkiException> {
                    bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)
                }

                exception.message shouldBe errorMessage
            }

            @Test
            fun `should not contain carriage returns`() = runTest {
                val memberCert = issueInvalidMemberCertificate("\r$USER_NAME")
                val bundle = MemberIdBundle(veraDnssecChain, ORG_CERT, memberCert)

                val exception = shouldThrow<PkiException> {
                    bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)
                }

                exception.message shouldBe errorMessage
            }

            @Test
            fun `should not contain line feeds`() = runTest {
                val memberCert = issueInvalidMemberCertificate("\n$USER_NAME")
                val bundle = MemberIdBundle(veraDnssecChain, ORG_CERT, memberCert)

                val exception = shouldThrow<PkiException> {
                    bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)
                }

                exception.message shouldBe errorMessage
            }

            private fun issueInvalidMemberCertificate(userName: String): MemberCertificate =
                MemberCertificate(
                    Certificate.issue(
                        userName,
                        MEMBER_KEY_PAIR.public,
                        ORG_KEY_PAIR.private,
                        ORG_CERT.validityPeriod.endInclusive,
                        ORG_CERT,
                        validityStartDate = ORG_CERT.validityPeriod.start,
                    ).certificateHolder,
                )
        }

        @Nested
        inner class DnssecChain {
            @Test
            fun `Service OID should be verified`() = runTest {
                val chainSpy = mockChain()
                val bundle = MemberIdBundle(chainSpy, ORG_CERT, MEMBER_CERT)

                bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)

                verify(chainSpy).verify(any(), eq(SERVICE_OID), any())
            }

            @Test
            fun `Key spec should match that set in TXT rdata`() = runTest {
                val chainSpy = mockChain()
                val bundle = MemberIdBundle(chainSpy, ORG_CERT, MEMBER_CERT)

                bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)

                verify(chainSpy).verify(eq(ORG_KEY_PAIR.public.orgKeySpec), any(), any())
            }

            @Test
            fun `Date period should intersect with specified one and the certificates`() = runTest {
                val memberCertStart = ORG_CERT.validityPeriod.start.plusSeconds(1)
                val memberCert = MemberCertificate.issue(
                    USER_NAME,
                    MEMBER_KEY_PAIR.public,
                    ORG_CERT,
                    ORG_KEY_PAIR.private,
                    ORG_CERT.validityPeriod.endInclusive,
                    memberCertStart,
                )
                val chainSpy = mockChain()
                val bundle = MemberIdBundle(chainSpy, ORG_CERT, memberCert)
                val verificationStart = memberCert.validityPeriod.start.minusSeconds(1)
                val verificationEnd = ORG_CERT.validityPeriod.endInclusive.minusSeconds(1)

                bundle.verify(SERVICE_OID, verificationStart..verificationEnd)

                verify(chainSpy).verify(any(), any(), eq(memberCertStart..verificationEnd))
            }

            @Test
            fun `Organisation name should match that of DNSSEC chain`() = runTest {
                val invalidChain = VeraDnssecChain("sub.$ORG_NAME", listOf(response))
                val bundle = MemberIdBundle(mockChain(invalidChain), ORG_CERT, MEMBER_CERT)

                val exception = shouldThrow<PkiException> {
                    bundle.verify(
                        SERVICE_OID,
                        ORG_CERT.validityPeriod,
                    )
                }

                exception.message shouldBe
                    "Organisation certificate does not correspond to DNSSEC chain"
            }

            @Test
            fun `DNS errors should be propagated`() = runTest {
                val originalException = DnsException("Oh-oh")
                val bundle = MemberIdBundle(mockChain(originalException), ORG_CERT, MEMBER_CERT)

                val exception = shouldThrow<PkiException> {
                    bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)
                }

                exception.message shouldBe "DNS/DNSSEC resolution failed"
                exception.cause shouldBe originalException
            }

            @Test
            fun `Vera DNSSEC chain verification errors should be propagated`() = runTest {
                val originalException = InvalidChainException("Oh-oh")
                val bundle = MemberIdBundle(mockChain(originalException), ORG_CERT, MEMBER_CERT)

                val exception = shouldThrow<PkiException> {
                    bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)
                }

                exception.message shouldBe "Vera DNSSEC chain verification failed"
                exception.cause shouldBe originalException
            }
        }

        @Nested
        inner class ValidResult {
            @Test
            fun `Organisation name should be output`() = runTest {
                val bundle = MemberIdBundle(mockChain(), ORG_CERT, MEMBER_CERT)

                val member = bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)

                member.orgName shouldBe ORG_NAME
            }

            @Test
            fun `User name should be output if member is a user`() = runTest {
                val bundle = MemberIdBundle(mockChain(), ORG_CERT, MEMBER_CERT)

                val member = bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)

                member.userName shouldBe USER_NAME
            }

            @Test
            fun `User name should not be output if member is a bot`() = runTest {
                val botCert = MemberCertificate.issue(
                    null,
                    MEMBER_KEY_PAIR.public,
                    ORG_CERT,
                    ORG_KEY_PAIR.private,
                    ORG_CERT.validityPeriod.endInclusive,
                    ORG_CERT.validityPeriod.start,
                )
                val bundle = MemberIdBundle(mockChain(), ORG_CERT, botCert)

                val member = bundle.verify(SERVICE_OID, ORG_CERT.validityPeriod)

                member.userName shouldBe null
            }
        }

        private suspend fun mockChain(chain: VeraDnssecChain = veraDnssecChain): VeraDnssecChain {
            val chainSpy = spy(chain)
            doReturn(Unit).whenever(chainSpy).verify(any(), any(), any())
            return chainSpy
        }

        private suspend fun mockChain(exc: Throwable): VeraDnssecChain {
            val chainSpy = spy(veraDnssecChain)
            doThrow(exc).whenever(chainSpy).verify(any(), any(), any())
            return chainSpy
        }
    }
}
