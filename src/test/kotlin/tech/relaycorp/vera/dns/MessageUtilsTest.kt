package tech.relaycorp.vera.dns

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.Type
import org.xbill.DNS.dnssec.ValidatingResolver

class MessageUtilsTest {
    @Nested
    inner class DnssecFailureDescription {
        private val failureReason = "Something went wrong"
        private val failureReasonEncoded = failureReason.toByteArray()
        private val failureReasonRecord: Record = Record.newRecord(
            Name.root,
            Type.TXT,
            ValidatingResolver.VALIDATION_REASON_QCLASS,
            42,
            byteArrayOf(failureReasonEncoded.size.toByte(), *failureReasonEncoded),
        )

        @Test
        fun `ADDITIONAL section should be present`() {
            val message = Message()

            message.dnssecFailureDescription shouldBe null
        }

        @Test
        fun `Record should be of type TXT`() {
            val invalidRecord = Record.newRecord(
                failureReasonRecord.name,
                Type.A,
                failureReasonRecord.dClass,
                failureReasonRecord.ttl,
                byteArrayOf(1, 1, 1, 1),
            )
            val message = Message()
            message.addRecord(invalidRecord, Section.ADDITIONAL)

            message.dnssecFailureDescription shouldBe null
        }

        @Test
        fun `Record name should be the root`() {
            val invalidRecord = Record.newRecord(
                Name.fromString(DnsTestStubs.DOMAIN_NAME),
                failureReasonRecord.type,
                failureReasonRecord.dClass,
                failureReasonRecord.ttl,
                failureReasonRecord.rdataToWireCanonical(),
            )
            val message = Message()
            message.addRecord(invalidRecord, Section.ADDITIONAL)

            message.dnssecFailureDescription shouldBe null
        }

        @Test
        fun `Record class should be that of DNSSEC validation reason`() {
            val invalidRecord = Record.newRecord(
                failureReasonRecord.name,
                failureReasonRecord.type,
                failureReasonRecord.dClass + 1,
                failureReasonRecord.ttl,
                failureReasonRecord.rdataToWireCanonical(),
            )
            val message = Message()
            message.addRecord(invalidRecord, Section.ADDITIONAL)

            message.dnssecFailureDescription shouldBe null
        }

        @Test
        fun `Reason should be extracted from valid record`() {
            val message = Message()
            message.addRecord(failureReasonRecord, Section.ADDITIONAL)

            message.dnssecFailureDescription shouldBe failureReason
        }
    }
}
