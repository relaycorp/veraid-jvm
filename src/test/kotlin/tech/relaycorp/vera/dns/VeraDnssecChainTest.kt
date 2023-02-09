package tech.relaycorp.vera.dns

import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.Message

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
            val responseSerialised = response.toWire()
            VeraDnssecChain.dnssecChainRetriever = makeRetriever(listOf(responseSerialised))

            val chain = VeraDnssecChain.retrieve(VeraStubs.ORGANISATION_NAME)

            chain.responses shouldHaveSize 1
            chain.responses.first() shouldBe responseSerialised
        }

        private fun makeRetriever(responses: List<ByteArray> = emptyList()): ChainRetriever =
            { domainName, recordType, resolverHostName ->
                retrieverCallArgs = RetrieverCallArgs(domainName, recordType, resolverHostName)
                DnssecChain(responses)
            }
    }
}
