package tech.relaycorp.vera.dns

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.beInstanceOf
import java.time.Instant
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSet
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Type
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
        fun `Responses should be stored in chain`() = runTest {
            val response = Message()
            response.header.id = 42
            VeraDnssecChain.dnssecChainRetriever = makeRetriever(listOf(response))

            val chain = VeraDnssecChain.retrieve(VeraStubs.ORGANISATION_NAME)

            chain.responses shouldHaveSize 1
            chain.responses.first() shouldBe response
        }

        @Test
        fun `Domain name should be stored in chain`() = runTest {
            VeraDnssecChain.dnssecChainRetriever = makeRetriever()

            val chain = VeraDnssecChain.retrieve(VeraStubs.ORGANISATION_NAME)

            chain.domainName shouldBe "_vera.${VeraStubs.ORGANISATION_NAME}."
        }

        private fun makeRetriever(responses: List<Message> = emptyList()): ChainRetriever =
            { domainName, recordType, resolverHostName ->
                retrieverCallArgs = RetrieverCallArgs(domainName, recordType, resolverHostName)
                DnssecChain(DnsStubs.DOMAIN_NAME, "TXT", responses)
            }
    }

    @Nested
    inner class Serialise {
        @Test
        fun `Responses should be wrapped in an explicitly tagged SET`() {
            val response1 = Message()
            val response2 = Message(response1.header.id + 1)
            val chain = VeraDnssecChain(VeraStubs.ORGANISATION_NAME, listOf(response1, response2))

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
                VeraDnssecChain.decode(VeraStubs.ORGANISATION_NAME, invalidSet)
            }

            error.message shouldBe "Chain SET contains non-OCTET STRING item (${DERNull.INSTANCE})"
        }

        @Test
        fun `Empty set should be supported`() {
            val set = DERSet()

            val chain = VeraDnssecChain.decode(VeraStubs.ORGANISATION_NAME, set)

            chain.responses shouldHaveSize 0
        }

        @Test
        fun `Malformed response should be refused`() {
            val vector = ASN1EncodableVector(1)
            vector.add(DEROctetString("malformed message".toByteArray()))
            val invalidSet = DERSet(vector)

            val error = shouldThrow<InvalidChainException> {
                VeraDnssecChain.decode(VeraStubs.ORGANISATION_NAME, invalidSet)
            }

            error.message shouldBe "Chain contains a malformed DNS message"
            error.cause should beInstanceOf<WireParseException>()
        }

        @Test
        fun `Chain should be initialised from valid SET`() {
            val response1 = Message()
            val response2 = Message(response1.header.id + 1)
            val chain = VeraDnssecChain(VeraStubs.ORGANISATION_NAME, listOf(response1, response2))
            val encoding = parseDer(chain.serialise()) as ASN1Set

            val chainDecoded = VeraDnssecChain.decode(VeraStubs.ORGANISATION_NAME, encoding)

            val responsesSerialised = chainDecoded.responses.map { it.toWire().asList() }
            responsesSerialised shouldContainExactlyInAnyOrder listOf(
                response1.toWire().asList(),
                response2.toWire().asList(),
            )
        }

        @Test
        fun `Organisation name should be stored`() {
            val response1 = Message()
            val chain = VeraDnssecChain(VeraStubs.ORGANISATION_NAME, listOf(response1))
            val encoding = parseDer(chain.serialise()) as ASN1Set

            val chainDecoded = VeraDnssecChain.decode(VeraStubs.ORGANISATION_NAME, encoding)

            chainDecoded.domainName shouldBe "_vera.${VeraStubs.ORGANISATION_NAME}."
        }
    }

    @Nested
    inner class Verify {
        private val orgKeySpec = VeraStubs.ORG_KEY_SPEC
        private val serviceOid = VeraStubs.SERVICE_OID

        private val now = Instant.now()
        private val datePeriod = now..now.plusSeconds(10)

        @Nested
        inner class VeraTxtResponse {
            @Test
            fun `Vera response should use the _vera subdomain`() {
                val record = RECORD.copy(name = Name.fromString(DnsStubs.DOMAIN_NAME))
                val response = record.makeResponse()
                val chain = VeraDnssecChain(VeraStubs.ORGANISATION_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "Chain is missing Vera TXT response"
            }

            @Test
            fun `Vera response should use the TXT record type`() {
                val record = Record.newRecord(
                    RECORD.name,
                    Type.A,
                    RECORD.dClass,
                    RECORD.ttl,
                    byteArrayOf(1, 1, 1, 1),
                )
                val response = record.makeResponse()
                val chain = VeraDnssecChain(VeraStubs.ORGANISATION_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "Chain is missing Vera TXT response"
            }

            @Test
            fun `Vera response should use the IN class`() {
                val record = RECORD.copy(dClass = RECORD.dClass + 1)
                val response = record.makeResponse()
                val chain = VeraDnssecChain(VeraStubs.ORGANISATION_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "Chain is missing Vera TXT response"
            }

            @Test
            fun `Multiple Vera TXT responses should be refused`() {
                val responses = listOf(RECORD.makeResponse(), RECORD.makeResponse())
                val chain = VeraDnssecChain(VeraStubs.ORGANISATION_NAME, responses)

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "Chain contains multiple Vera TXT responses"
            }

            @Test
            @Disabled
            fun `Rdata should be valid`() {
            }
        }

        @Nested
        inner class KeySpec {
            @Test
            @Disabled
            fun `Algorithm id should match that of specified key spec`() {
            }

            @Test
            @Disabled
            fun `Key id should match that of specified key spec`() {
            }
        }

        @Nested
        inner class ServiceOid {
            @Test
            @Disabled
            fun `Absence of service OID should allow any service`() {
            }

            @Test
            @Disabled
            fun `Presence of service OID should only allow matching service`() {
            }

            @Test
            @Disabled
            fun `Presence of service OID should only deny mismatching service`() {
            }

            @Test
            @Disabled
            fun `Explicit service OID should take precedence over wildcard`() {
            }
        }

        @Nested
        inner class DatePeriod {
            @Test
            @Disabled
            fun `There should be at least one message with an RRSig`() {
            }

            @Test
            @Disabled
            fun `Responses without RRSigs should be gracefully ignored if irrelevant`() {
            }

            @Test
            @Disabled
            fun `TTL override should truncate validity period of chain`() {
            }
        }

        @Test
        @Disabled
        fun `Valid chain should verify successfully`() {
        }
    }
}
