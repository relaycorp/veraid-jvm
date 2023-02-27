package tech.relaycorp.veraid.pki

import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Set
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.MEMBER_CERT
import tech.relaycorp.veraid.ORG_CERT
import tech.relaycorp.veraid.ORG_NAME
import tech.relaycorp.veraid.dns.RECORD
import tech.relaycorp.veraid.dns.VeraDnssecChain
import tech.relaycorp.veraid.dns.makeResponse
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
import tech.relaycorp.veraid.utils.x509.Certificate
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
}
