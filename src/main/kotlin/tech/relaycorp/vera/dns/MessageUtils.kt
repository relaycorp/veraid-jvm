@file:JvmName("MessageUtils")

package tech.relaycorp.vera.dns

import java.time.Instant
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Section
import org.xbill.DNS.TXTRecord
import org.xbill.DNS.Type
import org.xbill.DNS.dnssec.ValidatingResolver

internal val Message.dnssecFailureDescription: String?
    get() {
        val rrsets = this.getSectionRRsets(Section.ADDITIONAL)
        val rrset = rrsets.firstOrNull {
            it.name == Name.root &&
                it.type == Type.TXT &&
                it.dClass == ValidatingResolver.VALIDATION_REASON_QCLASS
        } ?: return null
        return (rrset.first() as TXTRecord).strings.first()
    }

internal val Message.signatureValidityPeriod: ClosedRange<Instant>?
    get() {
        val question = this.question
        val rrset = this.getSectionRRsets(Section.ANSWER).firstOrNull {
            question.sameRRset(it.first())
        } ?: return null
        if (rrset.sigs().isEmpty()) {
            return null
        }
        val latestSignatureInception = rrset.latestSignatureInception!!
        val earliestSignatureExpiry = rrset.earliestSignatureExpiry!!
        return latestSignatureInception..earliestSignatureExpiry
    }
