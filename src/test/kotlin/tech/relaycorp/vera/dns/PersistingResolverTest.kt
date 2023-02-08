package tech.relaycorp.vera.dns

import kotlin.test.assertTrue
import kotlinx.coroutines.future.await
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.Type

val QUERY_RECORD: Record =
    Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN)

class PersistingResolverTest {
    @Nested
    inner class Constructor {
        @Test
        fun `Specified resolver host name should be used`() {
            val resolver = PersistingResolver(DnsTestStubs.REMOTE_RESOLVER)

            assertEquals(DnsTestStubs.REMOTE_RESOLVER, resolver.address.hostString)
        }
    }

    @Nested
    inner class SendAsync {
        @Test
        fun `Persisted responses should be empty initially`() {
            val resolver = PersistingResolver(DnsTestStubs.REMOTE_RESOLVER)

            assertEquals(0, resolver.responses.size)
        }

        @Test
        fun `Responses should be persisted`() = runTest {
            val resolver = PersistingResolver(DnsTestStubs.REMOTE_RESOLVER)
            val queryMessage = Message.newQuery(QUERY_RECORD)

            resolver.sendAsync(queryMessage).await()

            assertEquals(1, resolver.responses.size)
            val response = resolver.responses.first()
            assertEquals(QUERY_RECORD, response.question)
            assertTrue(response.findRRset(QUERY_RECORD.name, QUERY_RECORD.type, Section.ANSWER))
        }
    }
}
