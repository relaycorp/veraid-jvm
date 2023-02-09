package tech.relaycorp.vera.dns

import org.xbill.DNS.Message
import org.xbill.DNS.SimpleResolver
import java.util.concurrent.CompletionStage
import java.util.concurrent.Executor

/**
 * DNSJava resolver that simply stores the responses it resolved.
 */
internal class PersistingResolver(hostName: String) : SimpleResolver(hostName) {
    private val _responses = mutableListOf<Message>()
    val responses: List<Message> = _responses

    override fun sendAsync(query: Message, executor: Executor?): CompletionStage<Message> {
        val result = super.sendAsync(query, executor)
        return result.thenApply { response ->
            _responses.add(response)
            response
        }
    }
}
