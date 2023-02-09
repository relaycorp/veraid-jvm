package tech.relaycorp.vera.dns

import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Section

internal fun Record.copy(
    name: Name? = null,
    type: Int? = null,
    dClass: Int? = null,
    rdata: ByteArray? = null
) =
    Record.newRecord(
        name ?: this.name,
        type ?: this.type,
        dClass ?: this.dClass,
        this.ttl,
        rdata ?: this.rdataToWireCanonical()
    )

internal fun Record.makeQuery() = Message.newQuery(this)

internal fun Record.makeResponse(): Message {
    val response = Message()
    response.header.setFlag(Flags.QR.toInt())
    response.addRecord(this, Section.QUESTION)
    response.addRecord(this, Section.ANSWER)
    return response
}
