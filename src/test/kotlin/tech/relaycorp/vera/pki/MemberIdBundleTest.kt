package tech.relaycorp.vera.pki

import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import java.math.BigInteger
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Set
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.vera.MEMBER_KEY_PAIR
import tech.relaycorp.vera.MEMBER_NAME
import tech.relaycorp.vera.ORG_KEY_PAIR
import tech.relaycorp.vera.ORG_NAME
import tech.relaycorp.vera.dns.RECORD
import tech.relaycorp.vera.dns.VeraDnssecChain
import tech.relaycorp.vera.dns.makeResponse
import tech.relaycorp.vera.utils.asn1.ASN1Utils
import tech.relaycorp.vera.utils.x509.Certificate

class MemberIdBundleTest {
    @Nested
    inner class Serialise {
        private val now = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS)
        private val response = RECORD.makeResponse()
        private val veraDnssecChain = VeraDnssecChain(ORG_NAME, listOf(response))
        private val orgCertificate = OrgCertificate.selfIssue(
            ORG_NAME,
            ORG_KEY_PAIR,
            now.plusSeconds(1),
            now,
        )
        private val memberCertificate = MemberCertificate.issue(
            MEMBER_NAME,
            MEMBER_KEY_PAIR.public,
            orgCertificate,
            ORG_KEY_PAIR.private,
            now.plusSeconds(1),
            now,
        )
        private val bundle = MemberIdBundle(veraDnssecChain, orgCertificate, memberCertificate)

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
                orgCertificate.certificateHolder
        }

        @Test
        fun `Member certificate should be included`() {
            val serialisation = bundle.serialise()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialisation)

            Certificate.decode(sequence[3]).certificateHolder shouldBe
                memberCertificate.certificateHolder
        }
    }
}
