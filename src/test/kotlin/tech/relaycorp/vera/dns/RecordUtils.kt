package tech.relaycorp.vera.dns

import java.time.Instant
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.TXTRecord

@Suppress("UNCHECKED_CAST")
internal fun <RecordType : Record> RecordType.copy(
    name: Name? = null,
    dClass: Int? = null,
    rdata: ByteArray? = null
): RecordType = Record.newRecord(
    name ?: this.name,
    this.type, // Type can't be changed without changing the Java class too
    dClass ?: this.dClass,
    this.ttl,
    rdata ?: this.rdataToWireCanonical()
) as RecordType

internal fun Record.makeQuery() = Message.newQuery(this)

internal fun Record.makeResponse(): Message {
    val response = Message()
    response.header.setFlag(Flags.QR.toInt())
    response.addRecord(this, Section.QUESTION)
    response.addRecord(this, Section.ANSWER)
    return response
}

val RECORD = TXTRecord(
    Name.fromString(DnsStubs.DOMAIN_NAME),
    DClass.IN,
    42,
    "foo"
)
private val now: Instant = Instant.now()
val RRSIG = RRSIGRecord(
    RECORD.name,
    RECORD.dClass,
    RECORD.ttl,
    RECORD.type,
    3,
    RECORD.ttl,
    now.plusSeconds(60),
    now,
    42,
    Name.root,
    "the signature".toByteArray()
)
