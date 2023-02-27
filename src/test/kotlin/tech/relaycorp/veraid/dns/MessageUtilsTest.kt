package tech.relaycorp.veraid.dns

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
    inner class GetRrset {
        private val question = RECORD.makeQuestion()

        @Test
        fun `Empty section should be ignored gracefully`() {
            val message = Message()

            message.getRrset(question, Section.ANSWER) shouldBe null
        }

        @Test
        fun `RRset should be taken from the specified section`() {
            val message = Message()
            val section = Section.ANSWER
            message.addRecord(RECORD, section)

            message.getRrset(question, section + 1) shouldBe null
        }

        @Test
        fun `RRset should match question name`() {
            val message = Message()
            message.addRecord(
                RECORD.copy(name = RECORD.name.makeSubdomain("sub")),
                Section.ANSWER,
            )

            message.getRrset(question, Section.ANSWER) shouldBe null
        }

        @Test
        fun `RRset should match question type`() {
            val message = Message()
            message.addRecord(
                Record.newRecord(
                    RECORD.name,
                    Type.A,
                    RECORD.dClass,
                    RECORD.ttl,
                    byteArrayOf(1, 1, 1, 1),
                ),
                Section.ANSWER,
            )

            message.getRrset(question, Section.ANSWER) shouldBe null
        }

        @Test
        fun `RRset should match question class`() {
            val message = Message()
            message.addRecord(
                RECORD.copy(dClass = RECORD.dClass + 1),
                Section.ANSWER,
            )

            message.getRrset(question, Section.ANSWER) shouldBe null
        }

        @Test
        fun `Matching RRset should be returned`() {
            val message = Message()
            message.addRecord(RECORD, Section.ANSWER)

            val rrset = message.getRrset(question, Section.ANSWER)
            rrset?.size() shouldBe 1
            rrset?.first() shouldBe RECORD
        }
    }

    @Nested
    inner class DnssecFailureDescription {
        private val failureReason = "Something went wrong"
        private val failureReasonRecord: Record = Record.newRecord(
            Name.root,
            Type.TXT,
            ValidatingResolver.VALIDATION_REASON_QCLASS,
            42,
            failureReason.toByteArray().txtRdataSerialise(),
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
                Name.fromString(DOMAIN_NAME),
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
        fun `Empty questions should result in null`() {
            val message = Message()

            message.signatureValidityPeriod shouldBe null
        }

        @Test
        fun `Empty answers should result in null`() {
            val message = RECORD.makeResponse()
            message.removeAllRecords(Section.ANSWER)

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
                RRSIG.signature,
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
                RRSIG.signature,
            )
            val message = RECORD.makeResponse()
            message.addRecord(RRSIG, Section.ANSWER)
            message.addRecord(olderRrsig, Section.ANSWER)

            message.signatureValidityPeriod?.endInclusive shouldBe olderRrsig.expire
        }

        @Test
        fun `Irrelevant RRset should be ignored`() {
            val irrelevantRecord = RECORD.copy(name = RECORD.name.makeSubdomain("sub"))
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
                RRSIG.signature,
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
                RRSIG.signature,
            )

            val message = RECORD.makeResponse()
            message.addRecord(RRSIG, Section.ANSWER)
            message.addRecord(additionalRrsig, Section.ANSWER)

            message.signatureValidityPeriod shouldBe RRSIG.timeSigned..additionalRrsig.expire
        }
    }
}
