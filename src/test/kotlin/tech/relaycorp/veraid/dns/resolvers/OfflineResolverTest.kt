package tech.relaycorp.veraid.dns.resolvers

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.future.await
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record
import org.xbill.DNS.Type
import tech.relaycorp.veraid.dns.DOMAIN_NAME
import tech.relaycorp.veraid.dns.copy
import tech.relaycorp.veraid.dns.makeQuery
import tech.relaycorp.veraid.dns.makeResponse
import tech.relaycorp.veraid.dns.makeSubdomain
import tech.relaycorp.veraid.dns.txtRdataSerialise

class OfflineResolverTest {
    private val record: Record = Record.newRecord(
        Name.fromString(DOMAIN_NAME),
        Type.TXT,
        DClass.IN,
        42,
        "the rdata".toByteArray().txtRdataSerialise(),
    )

    @Test
    fun `setPort should not be implemented`() {
        val resolver = OfflineResolver(emptyList())

        shouldThrow<NotImplementedError> {
            resolver.setPort(53)
        }
    }

    @Test
    fun `setTCP should not be implemented`() {
        val resolver = OfflineResolver(emptyList())

        shouldThrow<NotImplementedError> {
            resolver.setTCP(true)
        }
    }

    @Test
    fun `setIgnoreTruncation should do nothing`() {
        val resolver = OfflineResolver(emptyList())

        resolver.setIgnoreTruncation(true)
    }

    @Test
    fun `setEDNS should do nothing`() {
        val resolver = OfflineResolver(emptyList())

        resolver.setEDNS(1, 1, 1)
    }

    @Test
    fun `setTSIGKey should not be implemented`() {
        val resolver = OfflineResolver(emptyList())

        shouldThrow<NotImplementedError> {
            resolver.setTSIGKey(null)
        }
    }

    @Test
    fun `setTimeout should not be implemented`() {
        val resolver = OfflineResolver(emptyList())

        shouldThrow<NotImplementedError> {
            resolver.setTimeout(null)
        }
    }

    @Nested
    inner class SendAsync {
        @Nested
        inner class MissingResponse {
            private val query = Message.newQuery(record)

            @Test
            fun `Response message should be an actual response`() = runTest {
                val resolver = OfflineResolver(emptyList())

                val response = resolver.sendAsync(query).await()

                response.header.getFlag(Flags.QR.toInt()) shouldBe true
            }

            @Test
            fun `Response should be NXDOMAIN`() = runTest {
                val resolver = OfflineResolver(emptyList())

                val response = resolver.sendAsync(query).await()

                response.header.rcode shouldBe Rcode.NXDOMAIN
            }

            @Test
            fun `CD and AD flags should be disabled`() = runTest {
                val resolver = OfflineResolver(emptyList())

                val response = resolver.sendAsync(query).await()

                response.header.getFlag(Flags.CD.toInt()) shouldBe false
                response.header.getFlag(Flags.AD.toInt()) shouldBe false
            }

            @Test
            fun `Id should match that of query message`() = runTest {
                val resolver = OfflineResolver(emptyList())

                val response = resolver.sendAsync(query).await()

                response.header.id shouldBe query.header.id
            }
        }
    }

    @Test
    fun `Existing response shouldn't be returned unless the question name matches`() = runTest {
        val storedResponse = record.makeResponse()
        val resolver = OfflineResolver(listOf(storedResponse))
        val query = record.copy(name = record.name.makeSubdomain("sub")).makeQuery()

        val response = resolver.sendAsync(query).await()

        response shouldNotBe storedResponse
        response.rcode shouldBe Rcode.NXDOMAIN
    }

    @Test
    fun `Existing response shouldn't be returned unless the question type matches`() = runTest {
        val storedResponse = record.makeResponse()
        val resolver = OfflineResolver(listOf(storedResponse))
        val query = Record.newRecord(
            record.name,
            Type.A,
            record.dClass,
            record.ttl,
            byteArrayOf(1, 1, 1, 1),
        ).makeQuery()

        val response = resolver.sendAsync(query).await()

        response shouldNotBe storedResponse
        response.rcode shouldBe Rcode.NXDOMAIN
    }

    @Test
    fun `Question-less response shouldn't match question-less query`() = runTest {
        val storedResponse = Message()
        val resolver = OfflineResolver(listOf(storedResponse))
        val query = Message()

        val response = resolver.sendAsync(query).await()

        response shouldNotBe storedResponse
        response.rcode shouldBe Rcode.NXDOMAIN
        response.header.id shouldBe query.header.id
    }

    @Test
    fun `Existing response shouldn't be returned unless the question class matches`() = runTest {
        val storedResponse = record.makeResponse()
        val resolver = OfflineResolver(listOf(storedResponse))
        val query = record.copy(dClass = record.dClass + 1).makeQuery()

        val response = resolver.sendAsync(query).await()

        response shouldNotBe storedResponse
        response.rcode shouldBe Rcode.NXDOMAIN
        response.header.id shouldBe query.header.id
    }

    @Test
    fun `Existing response should be turned if query matches question`() = runTest {
        val storedResponse = record.makeResponse()
        val resolver = OfflineResolver(listOf(storedResponse))
        val query = record.makeQuery()

        val response = resolver.sendAsync(query).await()

        response shouldBe storedResponse
    }
}
