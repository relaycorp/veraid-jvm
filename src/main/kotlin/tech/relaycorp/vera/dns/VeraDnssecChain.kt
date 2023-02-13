package tech.relaycorp.vera.dns

import java.time.Instant
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSet
import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Type
import org.xbill.DNS.WireParseException
import tech.relaycorp.vera.OrganisationKeySpec

/**
 * Vera DNSSEC chain.
 *
 * It contains the DNSSEC chain for the Vera TXT RRSet (e.g., `_vera.example.com./TXT`).
 */
public class VeraDnssecChain internal constructor(
    organisationName: String,
    responses: List<Message>,
) : DnssecChain("_vera.$organisationName.", "TXT", responses) {
    /**
     * Serialise the chain.
     */
    public fun serialise(): ByteArray {
        val responsesWrapped = responses.map { DEROctetString(it.toWire()) }
        val vector = ASN1EncodableVector(responsesWrapped.size)
        vector.addAll(responsesWrapped.toTypedArray())
        return DERSet(vector).encoded
    }

    /**
     * Verify the chain
     */
    @Throws(DnsException::class)
    internal fun verify(
        organisationKeySpec: OrganisationKeySpec,
        serviceOid: ASN1ObjectIdentifier,
        datePeriod: ClosedRange<Instant>,
    ) {
        val veraTxtResponse = getVeraTxtResponse()
        TODO()
    }

    private fun getVeraTxtResponse(): Message {
        val veraRecordQuery =
            Record.newRecord(Name.fromString(domainName), Type.value(recordType), DClass.IN)
        val veraTxtResponses = responses.filter { it.question == veraRecordQuery }
        if (veraTxtResponses.isEmpty()) {
            throw InvalidChainException("Chain is missing Vera TXT response")
        }
        if (1 < veraTxtResponses.size) {
            // If DNSSEC verification were to succeed, we wouldn't know which message was used, so
            // we have to require exactly one response for the Vera TXT RRset. Without this check,
            // we could be reading the TTL override from a bogus response.
            throw InvalidChainException("Chain contains multiple Vera TXT responses")
        }
        return veraTxtResponses.single()
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
            val organisationNameNormalised = organisationName.trimEnd('.')
            val domainName = "_vera.$organisationNameNormalised."
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
