package tech.relaycorp.veraid.dns

import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.argumentCaptor
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.verify
import com.nhaarman.mockitokotlin2.whenever
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import kotlinx.coroutines.future.await
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.Isolated
import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Rcode
import org.xbill.DNS.Section
import org.xbill.DNS.SimpleResolver
import org.xbill.DNS.TXTRecord
import org.xbill.DNS.Type
import org.xbill.DNS.dnssec.ValidatingResolver
import tech.relaycorp.veraid.dns.resolvers.OfflineResolver
import tech.relaycorp.veraid.dns.resolvers.PersistingResolver
import java.io.ByteArrayInputStream
import java.nio.charset.Charset
import java.time.Clock
import java.time.Instant
import java.util.concurrent.CompletableFuture

class BaseDnssecChainTest {
    private val recordType = "TXT"

    @Nested
    @Isolated("We alter the resolver initialisers")
    inner class Retrieve {
        private val originalPersistingInitialiser = BaseDnssecChain.persistingResolverInitialiser
        private val originalValidatingInitialiser = BaseDnssecChain.onlineResolverInitialiser

        @BeforeEach
        fun storeOriginalInitialiser() {
            BaseDnssecChain.persistingResolverInitialiser = originalPersistingInitialiser
            BaseDnssecChain.onlineResolverInitialiser = originalValidatingInitialiser
        }

        @Test
        fun `Validating resolver should simply wrap specified resolver`() = runTest {
            val headResolver = mock<SimpleResolver>()
            val response = Message()
            whenever(headResolver.sendAsync(any())).thenReturn(
                CompletableFuture.completedFuture(response),
            )
            val validatingResolver = BaseDnssecChain.onlineResolverInitialiser(headResolver)
            val queryMessage = RECORD.makeQuery()

            validatingResolver.sendAsync(queryMessage).await()

            verify(headResolver).sendAsync(any())
        }

        @Test
        fun `Validating resolver should be configured with IANA root keys`() = runTest {
            val mockResolver = mockValidatingResolver()

            BaseDnssecChain.retrieve(DOMAIN_NAME, recordType, REMOTE_RESOLVER)

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
            BaseDnssecChain.persistingResolverInitialiser = { resolverHostName ->
                hostName = resolverHostName
                PersistingResolver(resolverHostName)
            }
            mockValidatingResolver()

            BaseDnssecChain.retrieve(DOMAIN_NAME, recordType, REMOTE_RESOLVER)

            hostName shouldBe REMOTE_RESOLVER
        }

        @Test
        fun `Specified domain name should be queried`() = runTest {
            val mockResolver = mockValidatingResolver()

            BaseDnssecChain.retrieve(DOMAIN_NAME, recordType, REMOTE_RESOLVER)

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.name.toString() shouldBe DOMAIN_NAME
            }
        }

        @Test
        fun `Specified record type should be queried`() = runTest {
            val mockResolver = mockValidatingResolver()

            BaseDnssecChain.retrieve(DOMAIN_NAME, recordType, REMOTE_RESOLVER)

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.type shouldBe Type.value(recordType)
            }
        }

        @Test
        fun `Queried record class should be IN`() = runTest {
            val mockResolver = mockValidatingResolver()

            BaseDnssecChain.retrieve(DOMAIN_NAME, recordType, REMOTE_RESOLVER)

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
                BaseDnssecChain.retrieve(
                    DOMAIN_NAME,
                    recordType,
                    REMOTE_RESOLVER,
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
                BaseDnssecChain.retrieve(
                    DOMAIN_NAME,
                    recordType,
                    REMOTE_RESOLVER,
                )
            }

            exception.message shouldStartWith "DNS lookup failed (NXDOMAIN)"
            exception.cause shouldBe null
        }

        @Test
        fun `Responses should be stored in chain`() = runTest {
            val record = TXTRecord(
                Name.fromString(DOMAIN_NAME),
                DClass.IN,
                42,
                "foo",
            )
            val response = record.makeResponse()
            mockPersistingResolver(response)
            mockValidatingResolver()

            val chain = BaseDnssecChain.retrieve(
                DOMAIN_NAME,
                recordType,
                REMOTE_RESOLVER,
            )

            chain.responses shouldHaveSize 1
            chain.responses.first() shouldBe response
        }

        @Test
        fun `Domain name should be stored in chain`() = runTest {
            mockValidatingResolver()

            val chain = BaseDnssecChain.retrieve(
                DOMAIN_NAME,
                recordType,
                REMOTE_RESOLVER,
            )

            chain.domainName shouldBe DOMAIN_NAME
        }

        @Test
        fun `Record type should be stored in chain`() = runTest {
            mockValidatingResolver()

            val chain = BaseDnssecChain.retrieve(
                DOMAIN_NAME,
                recordType,
                REMOTE_RESOLVER,
            )

            chain.recordType shouldBe recordType
        }

        private fun mockValidatingResolver(response: Message? = null): ValidatingResolver {
            val mockResolver = makeMockValidatingResolver(response)
            BaseDnssecChain.onlineResolverInitialiser = { mockResolver }
            return mockResolver
        }

        private fun mockPersistingResolver(response: Message): PersistingResolver {
            val mockResolver = mock<PersistingResolver>()
            whenever(mockResolver.sendAsync(any())).thenReturn(
                CompletableFuture.completedFuture(response),
            )
            whenever(mockResolver.responses).thenReturn(listOf(response))
            BaseDnssecChain.persistingResolverInitialiser = { mockResolver }
            return mockResolver
        }
    }

    @Nested
    @Isolated("We alter the resolver initialisers")
    inner class Verify {
        private val instant = Instant.now()

        private val originalValidatingInitialiser = BaseDnssecChain.offlineResolverInitialiser

        @BeforeEach
        fun storeOriginalInitialiser() {
            BaseDnssecChain.offlineResolverInitialiser = originalValidatingInitialiser
        }

        @Test
        fun `Offline resolver should be configured with stored responses`() = runTest {
            val chain = BaseDnssecChain(DOMAIN_NAME, recordType, listOf(Message()))
            var receivedHeadResolver: OfflineResolver? = null
            val mockResolver = makeMockValidatingResolver()
            BaseDnssecChain.offlineResolverInitialiser = { headResolver, _ ->
                receivedHeadResolver = headResolver
                mockResolver
            }

            chain.verify(instant)

            receivedHeadResolver?.responses shouldBe chain.responses
        }

        @Test
        fun `Validating resolver should wrap offline resolver`() = runTest {
            val headResolver = mock<OfflineResolver>()
            whenever(headResolver.sendAsync(any())).thenReturn(
                CompletableFuture.completedFuture(makeSuccessfulEmptyResponse()),
            )
            val validatingResolver =
                BaseDnssecChain.offlineResolverInitialiser(headResolver, Clock.systemUTC())
            val queryMessage = RECORD.makeQuery()

            validatingResolver.sendAsync(queryMessage).await()

            verify(headResolver).sendAsync(any())
        }

        @Test
        fun `Validating resolver should be configured with IANA root keys`() = runTest {
            val mockResolver = mockValidatingResolver()
            val chain = BaseDnssecChain(DOMAIN_NAME, recordType, listOf(Message()))

            chain.verify(instant)

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
            val chain = BaseDnssecChain(DOMAIN_NAME, recordType, listOf(Message()))

            chain.verify(instant)

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.name.toString() shouldBe DOMAIN_NAME
            }
        }

        @Test
        fun `Specified record type should be queried`() = runTest {
            val mockResolver = mockValidatingResolver()
            val chain = BaseDnssecChain(DOMAIN_NAME, recordType, listOf(Message()))

            chain.verify(instant)

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.type shouldBe Type.value(recordType)
            }
        }

        @Test
        fun `Queried record class should be IN`() = runTest {
            val mockResolver = mockValidatingResolver()
            val chain = BaseDnssecChain(DOMAIN_NAME, recordType, listOf(Message()))

            chain.verify(instant)

            argumentCaptor<Message>().apply {
                verify(mockResolver).sendAsync(capture())

                firstValue.question.dClass shouldBe DClass.IN
            }
        }

        @Test
        fun `Specified clock should be passed to validating resolver`() = runTest {
            val chain = BaseDnssecChain(DOMAIN_NAME, recordType, listOf(Message()))
            var receivedClock: Clock? = null
            val mockResolver = makeMockValidatingResolver()
            BaseDnssecChain.offlineResolverInitialiser = { _, clock ->
                receivedClock = clock
                mockResolver
            }

            chain.verify(instant)

            receivedClock?.instant() shouldBe instant
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
            val chain = BaseDnssecChain(DOMAIN_NAME, recordType, emptyList())

            val exception = shouldThrow<DnsException> {
                chain.verify(instant)
            }

            exception.message shouldBe "DNSSEC verification failed: $failureReason"
            exception.cause shouldBe null
        }

        @Test
        fun `Unsuccessful response should be refused`() = runTest {
            val response = makeSuccessfulEmptyResponse()
            response.header.rcode = Rcode.NXDOMAIN
            mockValidatingResolver(response)
            val chain = BaseDnssecChain(DOMAIN_NAME, recordType, emptyList())

            val exception = shouldThrow<DnsException> {
                chain.verify(instant)
            }

            exception.message shouldStartWith "DNS lookup failed (NXDOMAIN)"
            exception.cause shouldBe null
        }

        @Test
        fun `Valid chain should verify successfully`() = runTest {
            val record = TXTRecord(
                Name.fromString(DOMAIN_NAME),
                DClass.IN,
                42,
                "foo",
            )
            val response = makeSuccessfulEmptyResponse()
            response.addRecord(record, Section.ANSWER)
            mockValidatingResolver(response)
            val chain = BaseDnssecChain(DOMAIN_NAME, recordType, emptyList())

            chain.verify(instant)
        }

        private fun mockValidatingResolver(response: Message? = null): ValidatingResolver {
            val mockResolver = makeMockValidatingResolver(response)
            BaseDnssecChain.offlineResolverInitialiser = { _, _ -> mockResolver }
            return mockResolver
        }
    }
}
