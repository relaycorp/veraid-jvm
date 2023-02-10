package tech.relaycorp.vera.dns

import java.time.Instant
import org.xbill.DNS.RRset

internal val RRset.latestSignatureInception: Instant?
    get() {
        val rrsig = this.sigs().sortedByDescending { it.timeSigned }.firstOrNull()
        return rrsig?.timeSigned
    }

internal val RRset.earliestSignatureExpiry: Instant?
    get() {
        val rrsig = this.sigs().sortedBy { it.expire }.firstOrNull()
        return rrsig?.expire
    }
