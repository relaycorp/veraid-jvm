package tech.relaycorp.veraid.dns

import io.kotest.matchers.ints.shouldBeLessThan
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.TXTRecord
import tech.relaycorp.veraid.ORG_KEY_SPEC
import tech.relaycorp.veraid.SERVICE_OID
import java.time.Instant
import kotlin.math.pow
import kotlin.time.Duration.Companion.days

/**
 * Max size of TXT rdata fields (size must be representable with a single octet).
 */
private val maxTxtRdataSize = (2.toDouble().pow(8) - 1).toInt()

@Suppress("UNCHECKED_CAST")
internal fun <RecordType : Record> RecordType.copy(
    name: Name? = null,
    dClass: Int? = null,
    rdata: ByteArray? = null,
): RecordType = Record.newRecord(
    name ?: this.name,
    this.type, // Type can't be changed without changing the Java class too
    dClass ?: this.dClass,
    this.ttl,
    rdata ?: this.rdataToWireCanonical(),
) as RecordType

internal fun Record.makeQuestion() = Record.newRecord(name, type, dClass, ttl)

internal fun Record.makeRrsig(validityPeriod: DatePeriod) = RRSIGRecord(
    name,
    dClass,
    ttl,
    type,
    3,
    ttl,
    validityPeriod.endInclusive,
    validityPeriod.start,
    42,
    Name.root,
    "the signature".toByteArray(),
)

internal fun Record.makeQuery() = Message.newQuery(makeQuestion())

internal fun Record.makeResponse(): Message {
    val response = Message()
    response.header.setFlag(Flags.QR.toInt())
    response.addRecord(makeQuestion(), Section.QUESTION)
    response.addRecord(this, Section.ANSWER)
    return response
}

internal fun Record.makeResponseWithRrsig(validityPeriod: DatePeriod): Message {
    val response = makeResponse()
    response.addRecord(makeRrsig(validityPeriod), Section.ANSWER)
    return response
}

internal fun TXTRecord.copyWithDifferentRdata(fields: VeraRdataFields) = TXTRecord(
    name,
    dClass,
    ttl,
    fields.toString(),
)

internal fun ByteArray.txtRdataSerialise(): ByteArray {
    size shouldBeLessThan maxTxtRdataSize
    return byteArrayOf(size.toByte()) + this
}

internal val VERA_RDATA_FIELDS =
    VeraRdataFields(ORG_KEY_SPEC, 2.days, SERVICE_OID)
val RECORD = TXTRecord(
    Name.fromString("_vera.$DOMAIN_NAME"),
    DClass.IN,
    42,
    VERA_RDATA_FIELDS.toString(),
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
    "the signature".toByteArray(),
)
