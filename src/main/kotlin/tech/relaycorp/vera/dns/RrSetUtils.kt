package tech.relaycorp.vera.dns

import java.time.Instant
import org.xbill.DNS.RRset

internal val RRset.latestSignatureInception: Instant?
    get() {
        val rrsig = this.sigs().sortedBy { it.timeSigned }.firstOrNull()
        return rrsig?.timeSigned
    }
