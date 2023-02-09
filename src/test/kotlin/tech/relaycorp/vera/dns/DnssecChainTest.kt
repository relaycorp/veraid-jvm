package tech.relaycorp.vera.dns

import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.argumentCaptor
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.verify
import com.nhaarman.mockitokotlin2.whenever
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import java.io.ByteArrayInputStream
import java.nio.charset.Charset
import java.util.concurrent.CompletableFuture
import kotlinx.coroutines.future.await
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.Isolated
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.SimpleResolver
import org.xbill.DNS.TXTRecord
import org.xbill.DNS.Type
import org.xbill.DNS.dnssec.ValidatingResolver

class DnssecChainTest {
    @Nested
    @Isolated("We alter the resolver initialisers")
    inner class Retrieve {
        private val recordType = "TXT"

        private lateinit var originalPersistingInitialiser: PersistingResolverInitialiser
        private lateinit var originalValidatingInitialiser: ValidatingResolverInitialiser

        @BeforeEach
        fun storeOriginalInitialiser() {
            originalPersistingInitialiser = DnssecChain.persistingResolverInitialiser
            originalValidatingInitialiser = DnssecChain.validatingResolverInitialiser
        }

        @AfterEach
        fun restoreOriginalInitialiser() {
            DnssecChain.persistingResolverInitialiser = originalPersistingInitialiser
            DnssecChain.validatingResolverInitialiser = originalValidatingInitialiser
        }

        @Test
        fun `Validating resolver should simply wrap specified resolver`() = runTest {
            val headResolver = mock<SimpleResolver>()
            val response = Message()
            whenever(headResolver.sendAsync(any())).thenReturn(
                CompletableFuture.completedFuture(response)
            )
            val validatingResolver = DnssecChain.validatingResolverInitialiser(headResolver)
            val queryRecord = Record.newRecord(
                Name.fromString(DnsStubs.DOMAIN_NAME),
                Type.value(recordType),
                DClass.IN
            )
            val queryMessage = Message.newQuery(queryRecord)

            validatingResolver.sendAsync(queryMessage).await()

            verify(headResolver).sendAsync(any())
        }

        @Test
        fun `DNSSEC resolver should be configured with IANA root keys`() = runTest {
            val mockResolver = mockValidatingResolver()

            DnssecChain.retrieve(DnsStubs.DOMAIN_NAME, recordType, DnsStubs.REMOTE_RESOLVER)

            argumentCaptor<ByteArrayInputStream>().apply {
                verify(mockResolver).loadTrustAnchors(capture())

                firstValue.reset()
                val anchors = firstValue.readAllBytes().toString(Charset.defaultCharset())
                anchors shouldBe DnsUtils.DNSSEC_ROOT_DS
            }
        }

        @Test
        fun `Specified DNS resolver host should be honoured`() = runTest {
            var hostName: String? = null
            DnssecChain.persistingResolverInitialiser = { resolverHostName ->
                hostName = resolverHostName
                PersistingResolver(resolverHostName)
            }
            mockValidatingResolver()

            DnssecChain.retrieve(DnsStubs.DOMAIN_NAME, recordType, DnsStubs.REMOTE_RESOLVER)

            hostName shouldBe DnsStubs.REMOTE_RESOLVER
        }

        @Test
        fun `Specified domain name should be queried`() = runTest {
            val mockResolver = mockValidatingResolver()

            DnssecChain.retrieve(DnsStubs.DOMAIN_NAME, recordType, DnsStubs.REMOTE_RESOLVER)

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.name.toString() shouldBe DnsStubs.DOMAIN_NAME
            }
        }

        @Test
        fun `Specified record type should be queried`() = runTest {
            val mockResolver = mockValidatingResolver()

            DnssecChain.retrieve(DnsStubs.DOMAIN_NAME, recordType, DnsStubs.REMOTE_RESOLVER)

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.type shouldBe Type.value(recordType)
            }
        }

        @Test
        fun `Queried record class should be IN`() = runTest {
            val mockResolver = mockValidatingResolver()

            DnssecChain.retrieve(DnsStubs.DOMAIN_NAME, recordType, DnsStubs.REMOTE_RESOLVER)

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.dClass shouldBe DClass.IN
            }
        }

        @Test
        fun `Invalid DNSSEC chain should be refused`() = runTest {
            val response = Message()
            val failureReason = "Whoops"
            val failureRecord = TXTRecord(
                Name.root,
                ValidatingResolver.VALIDATION_REASON_QCLASS,
                42,
                failureReason,
            )
            response.addRecord(failureRecord, Section.ADDITIONAL)
            mockValidatingResolver(response)

            val exception = shouldThrow<DnsException> {
                DnssecChain.retrieve(
                    DnsStubs.DOMAIN_NAME,
                    recordType,
                    DnsStubs.REMOTE_RESOLVER
                )
            }

            exception.message shouldBe "DNSSEC verification failed: $failureReason"
            exception.cause shouldBe null
        }

        @Test
        fun `Unsuccessful responses should be refused`() = runTest {
            val response = Message()
            response.header.setFlag(Flags.AD.toInt())
            response.header.rcode = Rcode.NXDOMAIN
            mockValidatingResolver(response)

            val exception = shouldThrow<DnsException> {
                DnssecChain.retrieve(
                    DnsStubs.DOMAIN_NAME,
                    recordType,
                    DnsStubs.REMOTE_RESOLVER
                )
            }

            exception.message shouldStartWith "DNS lookup failed (NXDOMAIN)"
            exception.cause shouldBe null
        }

        @Test
        fun `Responses should be stored in chain`() = runTest {
            val record = TXTRecord(
                Name.fromString(DnsStubs.DOMAIN_NAME),
                DClass.IN,
                42,
                "foo"
            )
            val response = Message()
            response.addRecord(record, Section.ANSWER)
            mockPersistingResolver(response)
            mockValidatingResolver()

            val chain = DnssecChain.retrieve(
                DnsStubs.DOMAIN_NAME,
                recordType,
                DnsStubs.REMOTE_RESOLVER
            )

            chain.responses shouldHaveSize 1
            chain.responses.first() shouldBe response.toWire()
        }

        private fun mockValidatingResolver(response: Message? = null): ValidatingResolver {
            val defaultResponse = Message()
            defaultResponse.header.setFlag(Flags.AD.toInt())
            val finalResponse = response ?: defaultResponse
            val mockResolver = mock<ValidatingResolver>()
            whenever(mockResolver.sendAsync(any())).thenReturn(
                CompletableFuture.completedFuture(finalResponse)
            )
            DnssecChain.validatingResolverInitialiser = { mockResolver }
            return mockResolver
        }

        private fun mockPersistingResolver(response: Message): PersistingResolver {
            val mockResolver = mock<PersistingResolver>()
            whenever(mockResolver.sendAsync(any())).thenReturn(
                CompletableFuture.completedFuture(response)
            )
            whenever(mockResolver.responses).thenReturn(listOf(response))
            DnssecChain.persistingResolverInitialiser = { mockResolver }
            return mockResolver
        }
    }
}
