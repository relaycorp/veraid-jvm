package tech.relaycorp.veraid.dns

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSet
import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.TXTRecord
import org.xbill.DNS.Type
import org.xbill.DNS.WireParseException
import tech.relaycorp.veraid.DatePeriod
import tech.relaycorp.veraid.InstantPeriod
import tech.relaycorp.veraid.OrganisationKeySpec
import tech.relaycorp.veraid.toInstantPeriod
import tech.relaycorp.veraid.utils.intersect
import kotlin.time.toJavaDuration

/**
 * Vera DNSSEC chain.
 *
 * It contains the DNSSEC chain for the Vera TXT RRSet (e.g., `_veraid.example.com./TXT`).
 */
public class VeraDnssecChain internal constructor(
    internal val orgName: String,
    responses: List<Message>,
) : DnssecChain("_veraid.$orgName.", VERA_RECORD_TYPE, responses) {
    internal fun encode(): ASN1Set {
        val responsesWrapped = responses.map { DEROctetString(it.toWire()) }
        val vector = ASN1EncodableVector(responsesWrapped.size)
        vector.addAll(responsesWrapped.toTypedArray())
        return DERSet(vector)
    }

    /**
     * Serialise the chain.
     */
    public fun serialise(): ByteArray = encode().encoded

    /**
     * Verify the chain
     */
    @Throws(DnsException::class, InvalidChainException::class)
    internal suspend fun verify(
        orgKeySpec: OrganisationKeySpec,
        serviceOid: ASN1ObjectIdentifier,
        period: DatePeriod,
    ) {
        val verificationPeriod =
            calculateVerificationPeriod(period.toInstantPeriod(), orgKeySpec, serviceOid)
        val chainValidityPeriod = getChainValidityPeriod()
        val intersectingPeriod =
            verificationPeriod.intersect(chainValidityPeriod) ?: throw InvalidChainException(
                "Chain validity period does not overlap with required period",
            )
        super.verify(intersectingPeriod.start)
    }

    private fun getChainValidityPeriod(): InstantPeriod {
        val chainValidityPeriod = responses
            .mapNotNull { it.signatureValidityPeriod }.ifEmpty {
                throw InvalidChainException("Chain does not contain RRSig records")
            }
            .reduce { acc, period ->
                acc.intersect(period) ?: throw InvalidChainException(
                    "Chain contains RRSigs whose validity periods do not overlap",
                )
            }
        return chainValidityPeriod
    }

    private fun calculateVerificationPeriod(
        period: InstantPeriod,
        orgKeySpec: OrganisationKeySpec,
        serviceOid: ASN1ObjectIdentifier,
    ): InstantPeriod {
        val matchingFields = getRdataFields(orgKeySpec, serviceOid)
        val ttlOverride = matchingFields.ttlOverride
        val truncatedStart = period.endInclusive.minus(ttlOverride.toJavaDuration())
        val start = maxOf(period.start, truncatedStart)
        return start..period.endInclusive
    }

    private fun getRdataFields(
        orgKeySpec: OrganisationKeySpec,
        serviceOid: ASN1ObjectIdentifier,
    ): VeraRdataFields {
        val answers = getVeraTxtAnswers()
        val fieldSet = answers.map {
            val rdata = it.strings.singleOrNull() ?: throw InvalidChainException(
                "Vera TXT answer rdata must contain one string (got ${it.strings.size})",
            )
            try {
                VeraRdataFields.parse(rdata)
            } catch (exc: InvalidRdataException) {
                throw InvalidChainException("Vera TXT response contains invalid RDATA", exc)
            }
        }
        val matchingSet = fieldSet.filter {
            it.orgKeySpec == orgKeySpec && (it.service == null || it.service == serviceOid)
        }.ifEmpty {
            throw InvalidChainException("Could not find Vera record for specified key or service")
        }
        val concreteFields = matchingSet.filter { it.service == serviceOid }
        if (1 < concreteFields.size) {
            throw InvalidChainException("Found multiple Vera records for the same key and service")
        }
        val wildcardFields = matchingSet.filter { it.service == null }
        if (1 < wildcardFields.size) {
            throw InvalidChainException(
                "Found multiple Vera records for the same key and no service",
            )
        }
        return concreteFields.singleOrNull() ?: wildcardFields.single()
    }

    private fun getVeraTxtAnswers(): List<TXTRecord> {
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
        val veraTxtResponse = veraTxtResponses.single()
        val rrset = veraTxtResponse.getRrset(veraRecordQuery, Section.ANSWER)
            ?: throw InvalidChainException("Vera TXT response does not contain an answer")

        @Suppress("UNCHECKED_CAST")
        return rrset.rrs() as List<TXTRecord>
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
            resolverHost: String = CLOUDFLARE_RESOLVER,
        ): VeraDnssecChain {
            val organisationNameNormalised = organisationName.trimEnd('.')
            val domainName = "_veraid.$organisationNameNormalised."
            val dnssecChain = dnssecChainRetriever(domainName, VERA_RECORD_TYPE, resolverHost)
            return VeraDnssecChain(organisationName, dnssecChain.responses)
        }

        @Throws(DnsException::class)
        internal fun decode(organisationName: String, set: ASN1Set): VeraDnssecChain {
            val responses = set.map {
                if (it !is DEROctetString) {
                    throw InvalidChainException(
                        "Chain SET contains non-OCTET STRING item ($it)",
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
