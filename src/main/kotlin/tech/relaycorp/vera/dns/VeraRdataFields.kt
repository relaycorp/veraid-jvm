package tech.relaycorp.vera.dns

import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import tech.relaycorp.vera.KeyAlgorithm
import tech.relaycorp.vera.OrganisationKeySpec

internal data class VeraRdataFields(
    private val organisationKeySpec: OrganisationKeySpec,
    val ttlOverride: Duration,
    val service: ASN1ObjectIdentifier? = null,
) {
    companion object {
        private val MAX_TTL = 90.days

        @Throws(InvalidRdataException::class)
        fun parse(rdata: String): VeraRdataFields {
            val fieldsOrdered = rdata.trim().split("\\s+".toRegex())
            if (fieldsOrdered.size < 3) {
                throw InvalidRdataException(
                    "RDATA should have at least 3 space-separated fields " +
                        "(got ${fieldsOrdered.size})"
                )
            }

            val (keyAlgorithmIdRaw, keyId, ttlOverrideRaw) = fieldsOrdered

            val keyAlgorithmId = keyAlgorithmIdRaw.toIntOrNull()
                ?: throw InvalidRdataException("Malformed algorithm id ($keyAlgorithmIdRaw)")
            val keyAlgorithm = KeyAlgorithm[keyAlgorithmId]
                ?: throw InvalidRdataException("Unknown algorithm id ($keyAlgorithmId)")
            val keySpec = OrganisationKeySpec(keyAlgorithm, keyId)

            val ttlOverrideSeconds = ttlOverrideRaw.toUIntOrNull()
                ?: throw InvalidRdataException("Malformed TTL override ($ttlOverrideRaw)")
            val ttlOverride = ttlOverrideSeconds.toInt().seconds.coerceAtMost(MAX_TTL)

            val serviceOidRaw = fieldsOrdered.getOrNull(3)
            val serviceOid = if (serviceOidRaw != null)
                try {
                    ASN1ObjectIdentifier(serviceOidRaw)
                } catch (exc: IllegalArgumentException) {
                    throw InvalidRdataException("Malformed service OID ($serviceOidRaw)")
                }
            else
                null

            return VeraRdataFields(keySpec, ttlOverride, serviceOid)
        }
    }
}
