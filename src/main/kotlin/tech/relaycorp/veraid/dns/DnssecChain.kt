package tech.relaycorp.veraid.dns

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
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
import java.lang.IllegalStateException
import kotlin.time.toJavaDuration

/**
 * VeraId DNSSEC chain.
 *
 * It contains the DNSSEC chain for the VeraId TXT RRSet (e.g., `_veraid.example.com./TXT`).
 */
public class DnssecChain internal constructor(
    internal val orgName: String,
    responses: List<Message>,
) : BaseDnssecChain("_veraid.$orgName.", VERA_RECORD_TYPE, responses) {
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
    ): RdataFieldSet {
        val answers = getVeraTxtAnswers()
        val fieldSet = answers.map {
            val rdata = it.strings.singleOrNull() ?: throw InvalidChainException(
                "VeraId TXT answer rdata must contain one string (got ${it.strings.size})",
            )
            try {
                RdataFieldSet.parse(rdata)
            } catch (exc: InvalidRdataException) {
                throw InvalidChainException("VeraId TXT response contains invalid RDATA", exc)
            }
        }
        val matchingSet = fieldSet.filter {
            it.orgKeySpec == orgKeySpec && (it.service == null || it.service == serviceOid)
        }.ifEmpty {
            throw InvalidChainException("Could not find VeraId record for specified key or service")
        }
        val concreteFields = matchingSet.filter { it.service == serviceOid }
        if (1 < concreteFields.size) {
            throw InvalidChainException(
                "Found multiple VeraId records for the same key and service",
            )
        }
        val wildcardFields = matchingSet.filter { it.service == null }
        if (1 < wildcardFields.size) {
            throw InvalidChainException(
                "Found multiple VeraId records for the same key and no service",
            )
        }
        return concreteFields.singleOrNull() ?: wildcardFields.single()
    }

    private fun getVeraTxtAnswers(): List<TXTRecord> {
        val veraRecordQuery =
            Record.newRecord(Name.fromString(domainName), Type.value(recordType), DClass.IN)
        val veraTxtResponses = responses.filter { it.question == veraRecordQuery }
        if (veraTxtResponses.isEmpty()) {
            throw InvalidChainException("Chain is missing VeraId TXT response")
        }
        if (1 < veraTxtResponses.size) {
            // If DNSSEC verification were to succeed, we wouldn't know which message was used, so
            // we have to require exactly one response for the VeraId TXT RRset. Without this check,
            // we could be reading the TTL override from a bogus response.
            throw InvalidChainException("Chain contains multiple VeraId TXT responses")
        }
        val veraTxtResponse = veraTxtResponses.single()
        val rrset = veraTxtResponse.getRrset(veraRecordQuery, Section.ANSWER)
            ?: throw InvalidChainException("VeraId TXT response does not contain an answer")

        @Suppress("UNCHECKED_CAST")
        return rrset.rrs() as List<TXTRecord>
    }

    /**
     */
    public companion object {
        private const val VERA_RECORD_TYPE = "TXT"
        private const val CLOUDFLARE_RESOLVER = "1.1.1.1"

        internal var chainRetriever: ChainRetriever = BaseDnssecChain.Companion::retrieve

        /**
         * Retrieve VeraId DNSSEC chain for [organisationName].
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
        ): DnssecChain {
            val organisationNameNormalised = organisationName.trimEnd('.')
            val domainName = "_veraid.$organisationNameNormalised."
            val dnssecChain = chainRetriever(domainName, VERA_RECORD_TYPE, resolverHost)
            return DnssecChain(organisationName, dnssecChain.responses)
        }

        @Throws(InvalidChainException::class)
        internal fun decode(
            organisationName: String,
            setTagged: ASN1TaggedObject,
        ): DnssecChain {
            val set = try {
                ASN1Set.getInstance(setTagged, false)
            } catch (exc: IllegalStateException) {
                throw InvalidChainException("Chain is not an implicitly-tagged SET", exc)
            }
            return decode(organisationName, set)
        }

        @Throws(InvalidChainException::class)
        internal fun decode(organisationName: String, set: ASN1Set): DnssecChain {
            val responses = set.map {
                if (it !is DEROctetString) {
                    throw InvalidChainException(
                        "Chain SET contains non-OCTET STRING item (${it::class.simpleName})",
                    )
                }
                try {
                    Message(it.octets)
                } catch (exc: WireParseException) {
                    throw InvalidChainException("Chain contains a malformed DNS message", exc)
                }
            }
            return DnssecChain(organisationName, responses)
        }
    }
}
