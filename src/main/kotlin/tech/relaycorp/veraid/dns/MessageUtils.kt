@file:JvmName("MessageUtils")

package tech.relaycorp.veraid.dns

import java.time.Instant
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.RRset
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.TXTRecord
import org.xbill.DNS.Type
import org.xbill.DNS.dnssec.ValidatingResolver

internal fun Message.getRrset(question: Record, section: Int): RRset? {
    val sectionRrsets = getSectionRRsets(section)
    return sectionRrsets.firstOrNull { it.question == question }
}

internal val Message.dnssecFailureDescription: String?
    get() {
        val question =
            Record.newRecord(Name.root, Type.TXT, ValidatingResolver.VALIDATION_REASON_QCLASS)
        val rrset = getRrset(question, Section.ADDITIONAL) ?: return null
        return (rrset.first() as TXTRecord).strings.first()
    }

internal val Message.signatureValidityPeriod: ClosedRange<Instant>?
    get() {
        val question = this.question ?: return null
        val rrset = this.getRrset(question, Section.ANSWER) ?: return null
        return rrset.signatureValidityPeriod
    }
