package tech.relaycorp.vera.dns.resolvers

import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.future.await
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.DClass
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.Type
import tech.relaycorp.vera.dns.DnsStubs
import tech.relaycorp.vera.dns.makeQuery

val QUERY_RECORD: Record =
    Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN)

class PersistingResolverTest {
    @Nested
    inner class Constructor {
        @Test
        fun `Specified resolver host name should be used`() {
            val resolver = PersistingResolver(DnsStubs.REMOTE_RESOLVER)

            resolver.address.hostString shouldBe DnsStubs.REMOTE_RESOLVER
        }
    }

    @Nested
    inner class SendAsync {
        @Test
        fun `Persisted responses should be empty initially`() {
            val resolver = PersistingResolver(DnsStubs.REMOTE_RESOLVER)

            resolver.responses shouldHaveSize 0
        }

        @Test
        fun `Responses should be persisted`() = runTest {
            val resolver = PersistingResolver(DnsStubs.REMOTE_RESOLVER)

            resolver.sendAsync(QUERY_RECORD.makeQuery()).await()

            resolver.responses shouldHaveSize 1
            val response = resolver.responses.first()
            response.question shouldBe QUERY_RECORD
            response.findRRset(QUERY_RECORD.name, QUERY_RECORD.type, Section.ANSWER) shouldBe true
        }
    }
}
