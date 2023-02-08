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
import org.xbill.DNS.Type
import org.xbill.DNS.dnssec.ValidatingResolver

internal typealias DnssecResolverInitialiser = (resolverHostName: String) -> ValidatingResolver

internal class DnssecChain private constructor(val responses: List<ByteArray>) {
    companion object {
        private val DNSSEC_ROOT_DS = DnsUtils.DNSSEC_ROOT_DS.toByteArray(Charset.defaultCharset())

        var resolverInitialiser: DnssecResolverInitialiser =
            { hostName -> ValidatingResolver(PersistingResolver(hostName)) }

        suspend fun retrieve(
            domainName: String,
            recordType: String,
            resolverHostName: String
        ): DnssecChain {
            val resolver = resolverInitialiser(resolverHostName)
            resolver.loadTrustAnchors(ByteArrayInputStream(DNSSEC_ROOT_DS))

            val queryRecord =
                Record.newRecord(Name.fromString(domainName), Type.value(recordType), DClass.IN)
            val response = resolver.sendAsync(Message.newQuery(queryRecord)).await()

            if (!response.header.getFlag(Flags.AD.toInt())) {
                throw DnsException(
                    "DNSSEC verification failed: ${response.dnssecFailureDescription}"
                )
            }
            if (response.header.rcode != Rcode.NOERROR) {
                val rcodeName = Rcode.string(response.header.rcode)
                throw DnsException("DNS lookup failed ($rcodeName)")
            }

            return DnssecChain(emptyList())
        }
    }
}
