package tech.relaycorp.vera.dns

import java.time.Instant
import org.xbill.DNS.RRset

internal val RRset.signatureValidityPeriod: ClosedRange<Instant>?
    get() {
        val rrsigs = this.sigs().ifEmpty { return null }
        val start = rrsigs.sortedByDescending { it.timeSigned }.first().timeSigned
        val end = rrsigs.sortedBy { it.expire }.first().expire
        return start..end
    }
