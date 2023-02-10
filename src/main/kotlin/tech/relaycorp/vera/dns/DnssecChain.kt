package tech.relaycorp.vera.dns

import java.io.ByteArrayInputStream
import java.nio.charset.Charset
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
import tech.relaycorp.vera.dns.resolvers.PersistingResolver

internal typealias PersistingResolverInitialiser = (resolverHostName: String) -> PersistingResolver
internal typealias ValidatingResolverInitialiser = (headResolver: Resolver) -> ValidatingResolver

internal typealias ChainRetriever = suspend (
    domainName: String,
    recordType: String,
    resolverHostName: String
) -> DnssecChain

internal class DnssecChain internal constructor(val responses: List<Message>) {
    companion object {
        private val DNSSEC_ROOT_DS = DnsUtils.DNSSEC_ROOT_DS.toByteArray(Charset.defaultCharset())

        var persistingResolverInitialiser: PersistingResolverInitialiser =
            { hostName -> PersistingResolver(hostName) }
        var validatingResolverInitialiser: ValidatingResolverInitialiser =
            { resolver -> ValidatingResolver(resolver) }

        @JvmStatic
        @Throws(DnsException::class)
        suspend fun retrieve(
            domainName: String,
            recordType: String,
            resolverHostName: String
        ): DnssecChain {
            val persistingResolver = persistingResolverInitialiser(resolverHostName)
            val validatingResolver = validatingResolverInitialiser(persistingResolver)
            validatingResolver.loadTrustAnchors(ByteArrayInputStream(DNSSEC_ROOT_DS))

            val queryRecord =
                Record.newRecord(Name.fromString(domainName), Type.value(recordType), DClass.IN)
            val queryMessage = Message.newQuery(queryRecord)
            val response = validatingResolver.sendAsync(queryMessage).await()

            if (!response.header.getFlag(Flags.AD.toInt())) {
                throw DnsException(
                    "DNSSEC verification failed: ${response.dnssecFailureDescription}"
                )
            }
            if (response.header.rcode != Rcode.NOERROR) {
                val rcodeName = Rcode.string(response.header.rcode)
                throw DnsException("DNS lookup failed ($rcodeName)")
            }

            return DnssecChain(persistingResolver.responses)
        }
    }
}
