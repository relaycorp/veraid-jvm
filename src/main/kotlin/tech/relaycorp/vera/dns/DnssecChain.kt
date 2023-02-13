package tech.relaycorp.vera.dns

import java.io.ByteArrayInputStream
import java.nio.charset.Charset
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlinx.coroutines.future.await
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record
import org.xbill.DNS.Resolver
import org.xbill.DNS.Type
import org.xbill.DNS.dnssec.ValidatingResolver
import tech.relaycorp.vera.dns.resolvers.OfflineResolver
import tech.relaycorp.vera.dns.resolvers.PersistingResolver

internal typealias PersistingResolverInitialiser = (resolverHostName: String) -> PersistingResolver
internal typealias OnlineResolverInitialiser = (headResolver: Resolver) -> ValidatingResolver

internal typealias OfflineResolverInitialiser =
    (headResolver: OfflineResolver, clock: Clock) -> ValidatingResolver

internal typealias ChainRetriever = suspend (
    domainName: String,
    recordType: String,
    resolverHostName: String
) -> DnssecChain

/**
 * Vera-agnostic DNSSEC chain processing.
 */
public open class DnssecChain internal constructor(
    internal val domainName: String,
    internal val recordType: String,
    internal val responses: List<Message>
) {
    @Throws(DnsException::class)
    internal suspend fun verify(instant: Instant) {
        val offlineResolver = OfflineResolver(responses)
        val clock = Clock.fixed(instant, ZoneOffset.UTC)
        val validatingResolver = offlineResolverInitialiser(offlineResolver, clock)
        validatingResolver.resolve(domainName, recordType)
    }

    internal companion object {
        private val DNSSEC_ROOT_DS = DnsUtils.DNSSEC_ROOT_DS.toByteArray(Charset.defaultCharset())

        var persistingResolverInitialiser: PersistingResolverInitialiser =
            { hostName -> PersistingResolver(hostName) }
        var onlineResolverInitialiser: OnlineResolverInitialiser =
            { resolver -> ValidatingResolver(resolver) }

        var offlineResolverInitialiser: OfflineResolverInitialiser =
            { headResolver, clock -> ValidatingResolver(headResolver, clock) }

        @JvmStatic
        @Throws(DnsException::class)
        suspend fun retrieve(
            domainName: String,
            recordType: String,
            resolverHostName: String
        ): DnssecChain {
            val persistingResolver = persistingResolverInitialiser(resolverHostName)
            val validatingResolver = onlineResolverInitialiser(persistingResolver)
            validatingResolver.resolve(domainName, recordType)
            return DnssecChain(domainName, recordType, persistingResolver.responses)
        }

        @Throws(DnsException::class)
        private suspend fun ValidatingResolver.resolve(
            domainName: String,
            recordType: String
        ) {
            this.loadTrustAnchors(ByteArrayInputStream(DNSSEC_ROOT_DS))

            val queryRecord =
                Record.newRecord(Name.fromString(domainName), Type.value(recordType), DClass.IN)
            val queryMessage = Message.newQuery(queryRecord)
            val response = this.sendAsync(queryMessage).await()

            if (!response.header.getFlag(Flags.AD.toInt())) {
                throw DnsException(
                    "DNSSEC verification failed: ${response.dnssecFailureDescription}"
                )
            }
            if (response.header.rcode != Rcode.NOERROR) {
                val rcodeName = Rcode.string(response.header.rcode)
                throw DnsException("DNS lookup failed ($rcodeName)")
            }
        }
    }
}
