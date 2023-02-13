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
import java.time.Clock
import java.util.concurrent.CompletableFuture
import kotlinx.coroutines.future.await
import kotlinx.coroutines.test.runTest
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
import tech.relaycorp.vera.dns.resolvers.OfflineResolver
import tech.relaycorp.vera.dns.resolvers.PersistingResolver

class DnssecChainTest {
    private val recordType = "TXT"

    @Nested
    @Isolated("We alter the resolver initialisers")
    inner class Retrieve {
        private val originalPersistingInitialiser = DnssecChain.persistingResolverInitialiser
        private val originalValidatingInitialiser = DnssecChain.onlineResolverInitialiser

        @BeforeEach
        fun storeOriginalInitialiser() {
            DnssecChain.persistingResolverInitialiser = originalPersistingInitialiser
            DnssecChain.onlineResolverInitialiser = originalValidatingInitialiser
        }

        @Test
        fun `Validating resolver should simply wrap specified resolver`() = runTest {
            val headResolver = mock<SimpleResolver>()
            val response = Message()
            whenever(headResolver.sendAsync(any())).thenReturn(
                CompletableFuture.completedFuture(response)
            )
            val validatingResolver = DnssecChain.onlineResolverInitialiser(headResolver)
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
        fun `Validating resolver should be configured with IANA root keys`() = runTest {
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
            val response = makeSuccessfulEmptyResponse()
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
            chain.responses.first() shouldBe response
        }

        private fun mockValidatingResolver(response: Message? = null): ValidatingResolver {
            val mockResolver = makeMockValidatingResolver(response)
            DnssecChain.onlineResolverInitialiser = { mockResolver }
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

    @Nested
    @Isolated("We alter the resolver initialisers")
    inner class Verify {
        private val originalValidatingInitialiser = DnssecChain.offlineResolverInitialiser

        @BeforeEach
        fun storeOriginalInitialiser() {
            DnssecChain.offlineResolverInitialiser = originalValidatingInitialiser
        }

        @Test
        fun `Offline resolver should be configured with stored responses`() = runTest {
            val chain = DnssecChain(listOf(Message()))
            var receivedHeadResolver: OfflineResolver? = null
            val mockResolver = makeMockValidatingResolver()
            DnssecChain.offlineResolverInitialiser = { headResolver, _ ->
                receivedHeadResolver = headResolver
                mockResolver
            }

            chain.verify(DnsStubs.DOMAIN_NAME, recordType, Clock.systemUTC())

            receivedHeadResolver?.responses shouldBe chain.responses
        }

        @Test
        fun `Validating resolver should wrap offline resolver`() = runTest {
            val headResolver = mock<OfflineResolver>()
            whenever(headResolver.sendAsync(any())).thenReturn(
                CompletableFuture.completedFuture(makeSuccessfulEmptyResponse())
            )
            val validatingResolver =
                DnssecChain.offlineResolverInitialiser(headResolver, Clock.systemUTC())
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
        fun `Validating resolver should be configured with IANA root keys`() = runTest {
            val mockResolver = mockValidatingResolver()
            val chain = DnssecChain(listOf(Message()))

            chain.verify(DnsStubs.DOMAIN_NAME, recordType, Clock.systemUTC())

            argumentCaptor<ByteArrayInputStream>().apply {
                verify(mockResolver).loadTrustAnchors(capture())

                firstValue.reset()
                val anchors = firstValue.readAllBytes().toString(Charset.defaultCharset())
                anchors shouldBe DnsUtils.DNSSEC_ROOT_DS
            }
        }

        @Test
        fun `Specified domain name should be queried`() = runTest {
            val mockResolver = mockValidatingResolver()
            val chain = DnssecChain(listOf(Message()))

            chain.verify(DnsStubs.DOMAIN_NAME, recordType, Clock.systemUTC())

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.name.toString() shouldBe DnsStubs.DOMAIN_NAME
            }
        }

        @Test
        fun `Specified record type should be queried`() = runTest {
            val mockResolver = mockValidatingResolver()
            val chain = DnssecChain(listOf(Message()))

            chain.verify(DnsStubs.DOMAIN_NAME, recordType, Clock.systemUTC())

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.type shouldBe Type.value(recordType)
            }
        }

        @Test
        fun `Queried record class should be IN`() = runTest {
            val mockResolver = mockValidatingResolver()
            val chain = DnssecChain(listOf(Message()))

            chain.verify(DnsStubs.DOMAIN_NAME, recordType, Clock.systemUTC())

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.dClass shouldBe DClass.IN
            }
        }

        @Test
        fun `Specified clock should be passed to validating resolver`() = runTest {
            val chain = DnssecChain(listOf(Message()))
            var receivedClock: Clock? = null
            val mockResolver = makeMockValidatingResolver()
            DnssecChain.offlineResolverInitialiser = { _, clock ->
                receivedClock = clock
                mockResolver
            }
            val finalClock = Clock.systemUTC()

            chain.verify(DnsStubs.DOMAIN_NAME, recordType, finalClock)

            receivedClock shouldBe finalClock
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
            val chain = DnssecChain(emptyList())

            val exception = shouldThrow<DnsException> {
                chain.verify(DnsStubs.DOMAIN_NAME, recordType, Clock.systemUTC())
            }

            exception.message shouldBe "DNSSEC verification failed: $failureReason"
            exception.cause shouldBe null
        }

        @Test
        fun `Unsuccessful response should be refused`() = runTest {
            val response = makeSuccessfulEmptyResponse()
            response.header.rcode = Rcode.NXDOMAIN
            mockValidatingResolver(response)
            val chain = DnssecChain(emptyList())

            val exception = shouldThrow<DnsException> {
                chain.verify(DnsStubs.DOMAIN_NAME, recordType, Clock.systemUTC())
            }

            exception.message shouldStartWith "DNS lookup failed (NXDOMAIN)"
            exception.cause shouldBe null
        }

        @Test
        fun `Valid chain should verify successfully`() = runTest {
            val record = TXTRecord(
                Name.fromString(DnsStubs.DOMAIN_NAME),
                DClass.IN,
                42,
                "foo"
            )
            val response = makeSuccessfulEmptyResponse()
            response.addRecord(record, Section.ANSWER)
            mockValidatingResolver(response)
            val chain = DnssecChain(emptyList())

            chain.verify(DnsStubs.DOMAIN_NAME, recordType, Clock.systemUTC())
        }

        private fun mockValidatingResolver(response: Message? = null): ValidatingResolver {
            val mockResolver = makeMockValidatingResolver(response)
            DnssecChain.offlineResolverInitialiser = { _, _ -> mockResolver }
            return mockResolver
        }
    }

    private fun makeMockValidatingResolver(response: Message? = null): ValidatingResolver {
        val finalResponse = response ?: makeSuccessfulEmptyResponse()
        val mockResolver = mock<ValidatingResolver>()
        whenever(mockResolver.sendAsync(any())).thenReturn(
            CompletableFuture.completedFuture(finalResponse)
        )
        return mockResolver
    }

    private fun makeSuccessfulEmptyResponse(): Message {
        val response = Message()
        response.header.setFlag(Flags.AD.toInt())
        return response
    }
}
