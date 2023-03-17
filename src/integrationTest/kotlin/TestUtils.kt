import kotlinx.coroutines.delay
import tech.relaycorp.veraid.dns.VeraDnssecChain

suspend fun retrieveVeraidDnssecChain(orgName: String, maxRetries: Int): VeraDnssecChain {
    var result: VeraDnssecChain? = null
    var lastException: Throwable? = null
    for (i in 0 until maxRetries) {
        try {
            result = VeraDnssecChain.retrieve(orgName)
            break
        } catch (exc: Throwable) {
            lastException = exc
            delay(100)
        }
    }
    return result ?: throw Exception("Failed after $maxRetries retries", lastException)
}
