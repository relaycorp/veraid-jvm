import kotlinx.coroutines.delay
import tech.relaycorp.veraid.dns.DnssecChain

suspend fun retrieveVeraidDnssecChain(orgName: String, maxRetries: Int): DnssecChain {
    var result: DnssecChain? = null
    var lastException: Throwable? = null
    for (i in 0 until maxRetries) {
        try {
            result = DnssecChain.retrieve(orgName)
            break
        } catch (exc: Throwable) {
            lastException = exc
            delay(100)
        }
    }
    return result ?: throw Exception("Failed after $maxRetries retries", lastException)
}
