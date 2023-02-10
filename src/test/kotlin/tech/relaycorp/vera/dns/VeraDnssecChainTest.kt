package tech.relaycorp.vera.dns

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.beInstanceOf
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSet
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.Message
import org.xbill.DNS.WireParseException
import tech.relaycorp.vera.asn1.parseDer

data class RetrieverCallArgs(
    val domainName: String,
    val recordType: String,
    val resolverHost: String
)

class VeraDnssecChainTest {
    @Nested
    inner class Retrieve {
        private val originalChainRetriever = VeraDnssecChain.dnssecChainRetriever
        private var retrieverCallArgs: RetrieverCallArgs? = null

        @AfterEach
        fun restoreRetriever() {
            VeraDnssecChain.dnssecChainRetriever = originalChainRetriever
        }

        @BeforeEach
        fun resetRetrieverCallArgs() {
            retrieverCallArgs = null
        }

        @Test
        fun `Subdomain _vera of specified domain should be queried`() = runTest {
            VeraDnssecChain.dnssecChainRetriever = makeRetriever()

            VeraDnssecChain.retrieve(VeraStubs.ORGANISATION_NAME)

            retrieverCallArgs?.domainName shouldBe "_vera.${DnsStubs.DOMAIN_NAME}"
        }

        @Test
        fun `Trailing dot should be dropped from organisation name if present`() = runTest {
            VeraDnssecChain.dnssecChainRetriever = makeRetriever()

            VeraDnssecChain.retrieve(DnsStubs.DOMAIN_NAME)

            retrieverCallArgs?.domainName shouldBe "_vera.${DnsStubs.DOMAIN_NAME}"
        }

        @Test
        fun `TXT record type should be queried`() = runTest {
            VeraDnssecChain.dnssecChainRetriever = makeRetriever()

            VeraDnssecChain.retrieve(VeraStubs.ORGANISATION_NAME)

            retrieverCallArgs?.recordType shouldBe "TXT"
        }

        @Test
        fun `Cloudflare DNS resolver should be used by default`() = runTest {
            VeraDnssecChain.dnssecChainRetriever = makeRetriever()

            VeraDnssecChain.retrieve(VeraStubs.ORGANISATION_NAME)

            retrieverCallArgs?.resolverHost shouldBe "1.1.1.1"
        }

        @Test
        fun `Another DNS resolver should be used if explicitly set`() = runTest {
            val resolverHost = "1.2.3.4"
            VeraDnssecChain.dnssecChainRetriever = makeRetriever()

            VeraDnssecChain.retrieve(VeraStubs.ORGANISATION_NAME, resolverHost)

            retrieverCallArgs?.resolverHost shouldBe resolverHost
        }

        @Test
        fun `Responses should be stored in Vera chain`() = runTest {
            val response = Message()
            response.header.id = 42
            VeraDnssecChain.dnssecChainRetriever = makeRetriever(listOf(response))

            val chain = VeraDnssecChain.retrieve(VeraStubs.ORGANISATION_NAME)

            chain.responses shouldHaveSize 1
            chain.responses.first() shouldBe response
        }

        private fun makeRetriever(responses: List<Message> = emptyList()): ChainRetriever =
            { domainName, recordType, resolverHostName ->
                retrieverCallArgs = RetrieverCallArgs(domainName, recordType, resolverHostName)
                DnssecChain(responses)
            }
    }

    @Nested
    inner class Serialise {
        @Test
        fun `Responses should be wrapped in an explicitly tagged SET`() {
            val response1 = Message()
            val response2 = Message(response1.header.id + 1)
            val chain = VeraDnssecChain(listOf(response1, response2))

            val serialisation = chain.serialise()

            val asn1Set = parseDer(serialisation)
            val set = ASN1Set.getInstance(asn1Set)
            set shouldHaveSize 2
            set.first() should beInstanceOf<DEROctetString>()
            (set.first() as DEROctetString).octets shouldBe response1.toWire()
            set.last() should beInstanceOf<DEROctetString>()
            (set.last() as DEROctetString).octets shouldBe response2.toWire()
        }
    }

    @Nested
    inner class Decode {
        @Test
        fun `Non-OCTET STRING item should be refused`() {
            val vector = ASN1EncodableVector(1)
            vector.add(DERNull.INSTANCE)
            val invalidSet = DERSet(vector)

            val error = shouldThrow<InvalidChainException> {
                VeraDnssecChain.decode(invalidSet)
            }

            error.message shouldBe "Chain SET contains non-OCTET STRING item (${DERNull.INSTANCE})"
        }

        @Test
        fun `Empty set should be supported`() {
            val set = DERSet()

            val chain = VeraDnssecChain.decode(set)

            chain.responses shouldHaveSize 0
        }

        @Test
        fun `Malformed response should be refused`() {
            val vector = ASN1EncodableVector(1)
            vector.add(DEROctetString("malformed message".toByteArray()))
            val invalidSet = DERSet(vector)

            val error = shouldThrow<InvalidChainException> {
                VeraDnssecChain.decode(invalidSet)
            }

            error.message shouldBe "Chain contains a malformed DNS message"
            error.cause should beInstanceOf<WireParseException>()
        }

        @Test
        fun `Chain should be initialised from valid SET`() {
            val response1 = Message()
            val response2 = Message(response1.header.id + 1)
            val chain = VeraDnssecChain(listOf(response1, response2))
            val encoding = parseDer(chain.serialise()) as ASN1Set

            val chainDecoded = VeraDnssecChain.decode(encoding)

            val responsesSerialised = chainDecoded.responses.map { it.toWire().asList() }
            responsesSerialised shouldContainExactlyInAnyOrder listOf(
                response1.toWire().asList(),
                response2.toWire().asList(),
            )
        }
    }
}
