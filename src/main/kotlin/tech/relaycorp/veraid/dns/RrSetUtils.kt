@file:JvmName("RrSetUtils")

package tech.relaycorp.veraid.dns

import org.xbill.DNS.RRset
import org.xbill.DNS.Record
import tech.relaycorp.veraid.DatePeriod

internal val RRset.question: Record
    get() = Record.newRecord(name, type, dClass)

internal val RRset.signatureValidityPeriod: DatePeriod?
    get() {
        val rrsigs = this.sigs().ifEmpty { return null }
        val start = rrsigs.sortedByDescending { it.timeSigned }.first().timeSigned
        val end = rrsigs.sortedBy { it.expire }.first().expire
        return start..end
    }
