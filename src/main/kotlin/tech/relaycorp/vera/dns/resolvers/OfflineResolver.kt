package tech.relaycorp.vera.dns.resolvers

import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import java.util.concurrent.Executor
import org.xbill.DNS.EDNSOption
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Rcode
import org.xbill.DNS.Resolver
import org.xbill.DNS.TSIG

internal class OfflineResolver(private val responses: List<Message>) : Resolver {
    override fun sendAsync(query: Message, executor: Executor?): CompletionStage<Message> {
        val response = responses.firstOrNull { it.question == query.question }
            ?: makeNxdomainResponse(query.header.id)
        return CompletableFuture.completedFuture(response)
    }

    private fun makeNxdomainResponse(queryId: Int): Message {
        val response = Message()
        response.header.rcode = Rcode.NXDOMAIN
        response.header.id = queryId
        response.header.setFlag(Flags.QR.toInt())
        return response
    }

    override fun setPort(port: Int) = throw NotImplementedError()

    override fun setTCP(flag: Boolean) = throw NotImplementedError()

    override fun setIgnoreTruncation(flag: Boolean) = throw NotImplementedError()

    override fun setEDNS(
        version: Int,
        payloadSize: Int,
        flags: Int,
        options: MutableList<EDNSOption>?
    ) = throw NotImplementedError()

    override fun setTSIGKey(key: TSIG?) = throw NotImplementedError()

    override fun setTimeout(timeout: Duration?) = throw NotImplementedError()
}
