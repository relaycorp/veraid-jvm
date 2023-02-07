package tech.relaycorp.vera.dns

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Type

const val REMOTE_RESOLVER_HOST = "8.8.8.8"
val QUERY_RECORD: Record =
    Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN)

class PersistingResolverTest {
    @Nested
    inner class Constructor {
        @Test
        fun `Specified resolver host name should be used`() {
            val resolver = PersistingResolver(REMOTE_RESOLVER_HOST)

            assertEquals(REMOTE_RESOLVER_HOST, resolver.address.hostString)
        }
    }

    @Nested
    inner class SendAsync {
        @Test
        fun `Persisted responses should be empty initially`() {
            val resolver = PersistingResolver(REMOTE_RESOLVER_HOST)

            assertEquals(0, resolver.responses.size)
        }

        @Test
        fun `Responses should be persisted`() {
            val resolver = PersistingResolver(REMOTE_RESOLVER_HOST)
            val queryMessage = Message.newQuery(QUERY_RECORD)

            resolver.sendAsync(queryMessage).toCompletableFuture().join()

            assertEquals(1, resolver.responses.size)
            assertEquals(QUERY_RECORD, resolver.responses.first().question)
        }
    }
}
