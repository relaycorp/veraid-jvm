package tech.relaycorp.vera.dns

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
