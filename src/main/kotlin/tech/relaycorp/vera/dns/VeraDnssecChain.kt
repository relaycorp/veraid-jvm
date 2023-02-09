package tech.relaycorp.vera.dns

public class VeraDnssecChain private constructor(internal val responses: List<ByteArray>) {
    public companion object {
        private const val VERA_RECORD_TYPE = "TXT"
        private const val CLOUDFLARE_RESOLVER = "1.1.1.1"

        internal var dnssecChainRetriever: ChainRetriever = DnssecChain.Companion::retrieve

        @JvmStatic
        public suspend fun retrieve(
            organisationName: String,
            resolverHost: String = CLOUDFLARE_RESOLVER
        ): VeraDnssecChain {
            val domainName = "_vera.${organisationName.trimEnd('.')}."
            val dnssecChain = dnssecChainRetriever(domainName, VERA_RECORD_TYPE, resolverHost)
            return VeraDnssecChain(dnssecChain.responses)
        }
    }
}
