package tech.relaycorp.vera.dns

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.RRSIGRecord
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
                Name.fromString(DnsStubs.DOMAIN_NAME),
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

    @Nested
    inner class SignatureValidityPeriod {
        @Test
        fun `Empty answers should result in null`() {
            val message = Message()

            message.signatureValidityPeriod shouldBe null
        }

        @Test
        fun `Unsigned answer should result in null`() {
            val message = RECORD.makeResponse()

            message.signatureValidityPeriod shouldBe null
        }

        @Test
        fun `Period should be that of sole answer`() {
            val message = RECORD.makeResponse()
            message.addRecord(RRSIG, Section.ANSWER)

            message.signatureValidityPeriod shouldBe RRSIG.timeSigned..RRSIG.expire
        }

        @Test
        fun `Inception time should be that of latest RRSig`() {
            val newerRrsig = RRSIGRecord(
                RRSIG.name,
                RRSIG.dClass,
                RRSIG.ttl,
                RRSIG.typeCovered,
                RRSIG.algorithm,
                RRSIG.origTTL,
                RRSIG.timeSigned.plusSeconds(1),
                RRSIG.expire,
                RRSIG.footprint,
                RRSIG.signer,
                RRSIG.signature
            )
            val message = RECORD.makeResponse()
            message.addRecord(RRSIG, Section.ANSWER)
            message.addRecord(newerRrsig, Section.ANSWER)

            message.signatureValidityPeriod?.start shouldBe newerRrsig.timeSigned
        }

        @Test
        fun `Expiry time should be that of earliest RRSig`() {
            val olderRrsig = RRSIGRecord(
                RRSIG.name,
                RRSIG.dClass,
                RRSIG.ttl,
                RRSIG.typeCovered,
                RRSIG.algorithm,
                RRSIG.origTTL,
                RRSIG.expire.minusSeconds(1),
                RRSIG.timeSigned,
                RRSIG.footprint,
                RRSIG.signer,
                RRSIG.signature
            )
            val message = RECORD.makeResponse()
            message.addRecord(RRSIG, Section.ANSWER)
            message.addRecord(olderRrsig, Section.ANSWER)

            message.signatureValidityPeriod?.endInclusive shouldBe olderRrsig.expire
        }

        @Test
        fun `Irrelevant RRset should be ignored`() {
            val irrelevantRecord = RECORD.copy(name = Name("subdomain", RECORD.name))
            val irrelevantRrsig = RRSIGRecord(
                irrelevantRecord.name,
                RRSIG.dClass,
                RRSIG.ttl,
                RRSIG.typeCovered,
                RRSIG.algorithm,
                RRSIG.origTTL,
                RRSIG.expire.minusSeconds(1),
                RRSIG.timeSigned.plusSeconds(1),
                RRSIG.footprint,
                RRSIG.signer,
                RRSIG.signature
            )

            val message = RECORD.makeResponse()
            message.addRecord(RRSIG, Section.ANSWER)
            message.addRecord(irrelevantRecord, Section.ANSWER)
            message.addRecord(irrelevantRrsig, Section.ANSWER)

            message.signatureValidityPeriod shouldBe RRSIG.timeSigned..RRSIG.expire
        }

        @Test
        fun `Multiple matching RRSIGs should be considered`() {
            val additionalRrsig = RRSIGRecord(
                RRSIG.name,
                RRSIG.dClass,
                RRSIG.ttl,
                RRSIG.typeCovered,
                RRSIG.algorithm,
                RRSIG.origTTL,
                RRSIG.expire.minusSeconds(1),
                RRSIG.timeSigned,
                RRSIG.footprint,
                RRSIG.signer,
                RRSIG.signature
            )

            val message = RECORD.makeResponse()
            message.addRecord(RRSIG, Section.ANSWER)
            message.addRecord(additionalRrsig, Section.ANSWER)

            message.signatureValidityPeriod shouldBe RRSIG.timeSigned..additionalRrsig.expire
        }
    }
}
