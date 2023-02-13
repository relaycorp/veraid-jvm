package tech.relaycorp.vera.dns

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSet
import org.xbill.DNS.Message
import org.xbill.DNS.WireParseException

/**
 * Vera DNSSEC chain.
 *
 * It contains the DNSSEC chain for the Vera TXT RRSet (e.g., `_vera.example.com./TXT`).
 */
public class VeraDnssecChain internal constructor(
    organisationName: String,
    responses: List<Message>,
) : DnssecChain(organisationName, "TXT", responses) {
    /**
     * Serialise the chain.
     */
    public fun serialise(): ByteArray {
        val responsesWrapped = responses.map { DEROctetString(it.toWire()) }
        val vector = ASN1EncodableVector(responsesWrapped.size)
        vector.addAll(responsesWrapped.toTypedArray())
        return DERSet(vector).encoded
    }

    public companion object {
        private const val VERA_RECORD_TYPE = "TXT"
        private const val CLOUDFLARE_RESOLVER = "1.1.1.1"

        internal var dnssecChainRetriever: ChainRetriever = DnssecChain.Companion::retrieve

        /**
         * Retrieve Vera DNSSEC chain for [organisationName].
         *
         * @param organisationName The domain name of the organisation
         * @param resolverHost The IPv4 address for the DNSSEC-aware, recursive resolver
         * @throws DnsException if there was a DNS- or DNSSEC-related error
         */
        @JvmStatic
        @Throws(DnsException::class)
        public suspend fun retrieve(
            organisationName: String,
            resolverHost: String = CLOUDFLARE_RESOLVER
        ): VeraDnssecChain {
            val domainName = "_vera.${organisationName.trimEnd('.')}."
            val dnssecChain = dnssecChainRetriever(domainName, VERA_RECORD_TYPE, resolverHost)
            return VeraDnssecChain(organisationName, dnssecChain.responses)
        }

        @Throws(DnsException::class)
        internal fun decode(organisationName: String, set: ASN1Set): VeraDnssecChain {
            val responses = set.map {
                if (it !is DEROctetString) {
                    throw InvalidChainException(
                        "Chain SET contains non-OCTET STRING item ($it)"
                    )
                }
                try {
                    Message(it.octets)
                } catch (exc: WireParseException) {
                    throw InvalidChainException("Chain contains a malformed DNS message", exc)
                }
            }
            return VeraDnssecChain(organisationName, responses)
        }
    }
}
