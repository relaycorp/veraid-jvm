package tech.relaycorp.vera.dns

import com.nhaarman.mockitokotlin2.argumentCaptor
import com.nhaarman.mockitokotlin2.spy
import com.nhaarman.mockitokotlin2.verify
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.inspectors.forOne
import io.kotest.matchers.collections.shouldHaveAtLeastSize
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import java.io.ByteArrayInputStream
import java.nio.charset.Charset
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.Isolated
import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Section
import org.xbill.DNS.SimpleResolver
import org.xbill.DNS.Type
import org.xbill.DNS.dnssec.ValidatingResolver

class DnssecChainTest {
    @Nested
    @Isolated("We alter the resolver initialisers")
    inner class Retrieve {
        private val recordType = "A"

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
        fun `DNSSEC resolver should be configured with IANA root keys`() = runTest {
            val spiedResolver = spy(makeValidatingResolver())
            DnssecChain.validatingResolverInitialiser = { spiedResolver }

            DnssecChain.retrieve(DnsTestStubs.DOMAIN_NAME, recordType, DnsTestStubs.REMOTE_RESOLVER)

            argumentCaptor<ByteArrayInputStream>().apply {
                verify(spiedResolver).loadTrustAnchors(capture())

                firstValue.reset()
                val anchors = firstValue.readAllBytes().toString(Charset.defaultCharset())
                assertEquals(DnsUtils.DNSSEC_ROOT_DS, anchors)
            }
        }

        @Test
        fun `Specified DNS resolver host should be honoured`() = runTest {
            var hostName: String? = null
            DnssecChain.persistingResolverInitialiser = { resolverHostName ->
                hostName = resolverHostName
                PersistingResolver(resolverHostName)
            }

            DnssecChain.retrieve(DnsTestStubs.DOMAIN_NAME, recordType, DnsTestStubs.REMOTE_RESOLVER)

            hostName shouldBe DnsTestStubs.REMOTE_RESOLVER
        }

        @Test
        fun `Specified domain name should be queried`() = runTest {
            val spiedResolver = spy(makeValidatingResolver())
            DnssecChain.validatingResolverInitialiser = { spiedResolver }

            DnssecChain.retrieve(DnsTestStubs.DOMAIN_NAME, recordType, DnsTestStubs.REMOTE_RESOLVER)

            argumentCaptor<Message>().apply {
                verify(spiedResolver).sendAsync(capture())

                assertEquals(DnsTestStubs.DOMAIN_NAME, firstValue.question.name.toString())
            }
        }

        @Test
        fun `Specified record type should be queried`() = runTest {
            val spiedResolver = spy(makeValidatingResolver())
            DnssecChain.validatingResolverInitialiser = { spiedResolver }

            DnssecChain.retrieve(DnsTestStubs.DOMAIN_NAME, recordType, DnsTestStubs.REMOTE_RESOLVER)

            argumentCaptor<Message>().apply {
                verify(spiedResolver).sendAsync(capture())

                assertEquals(Type.value(recordType), firstValue.question.type)
            }
        }

        @Test
        fun `Queried record class should be IN`() = runTest {
            val spiedResolver = spy(makeValidatingResolver())
            DnssecChain.validatingResolverInitialiser = { spiedResolver }

            DnssecChain.retrieve(DnsTestStubs.DOMAIN_NAME, recordType, DnsTestStubs.REMOTE_RESOLVER)

            argumentCaptor<Message>().apply {
                verify(spiedResolver).sendAsync(capture())

                assertEquals(DClass.IN, firstValue.question.dClass)
            }
        }

        @Test
        fun `Invalid DNSSEC chain should be refused`() = runTest {
            val domainName = "dnssec-failed.org."
            val exception = shouldThrow<DnsException> {
                DnssecChain.retrieve(domainName, recordType, DnsTestStubs.REMOTE_RESOLVER)
            }

            exception.message shouldStartWith "DNSSEC verification failed: " +
                "Could not establish a chain of trust to keys for [$domainName]"
            exception.cause shouldBe null
        }

        @Test
        fun `Unsuccessful responses should be refused`() = runTest {
            val domainName = "hard-to-believe-this-will-ever-exist.${DnsTestStubs.DOMAIN_NAME}"
            val exception = shouldThrow<DnsException> {
                DnssecChain.retrieve(domainName, recordType, DnsTestStubs.REMOTE_RESOLVER)
            }

            exception.message shouldStartWith "DNS lookup failed (NXDOMAIN)"
            exception.cause shouldBe null
        }

        @Test
        fun `Responses should be stored in chain`() = runTest {
            val chain = DnssecChain.retrieve(
                DnsTestStubs.DOMAIN_NAME,
                recordType,
                DnsTestStubs.REMOTE_RESOLVER
            )

            chain.responses shouldHaveAtLeastSize 1
            val responses = chain.responses.map { Message(it) }
            responses.forOne { response ->
                val answers = response.getSectionRRsets(Section.ANSWER)
                answers shouldHaveSingleElement { rrset ->
                    rrset.name.toString() == DnsTestStubs.DOMAIN_NAME &&
                        rrset.type == Type.value(recordType)
                }
            }
        }

        private fun makeValidatingResolver() =
            ValidatingResolver(SimpleResolver(DnsTestStubs.REMOTE_RESOLVER))
    }
}
