package tech.relaycorp.vera.dns

import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldHaveLength
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.RRset

class RrSetUtilsTest {
    @Nested
    inner class Question {
        private val rrset = RRset(RECORD)

        @Test
        fun `Name should be that of records`() {
            rrset.question.name shouldBe RECORD.name
        }

        @Test
        fun `Type should be that of records`() {
            rrset.question.type shouldBe RECORD.type
        }

        @Test
        fun `Class should be that of records`() {
            rrset.question.dClass shouldBe RECORD.dClass
        }

        @Test
        fun `TTL should be unset`() {
            rrset.question.ttl shouldBe 0
        }

        @Test
        fun `Rdata should be unset`() {
            rrset.question.rdataToString() shouldHaveLength 0
        }
    }

    @Nested
    inner class SignatureValidityPeriod {
        @Test
        fun `Unsigned RRset should result in null`() {
            val rrset = RRset(RECORD)

            rrset.signatureValidityPeriod shouldBe null
        }

        @Test
        fun `Period should be that of sole signature`() {
            val rrset = RRset(RECORD, RRSIG)

            rrset.signatureValidityPeriod shouldBe RRSIG.timeSigned..RRSIG.expire
        }

        @Test
        fun `Inception time should be that of latest signature inceptions`() {
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
            val rrset = RRset(RECORD, RRSIG, newerRrsig)

            rrset.signatureValidityPeriod?.start shouldBe newerRrsig.timeSigned
        }

        @Test
        fun `Expiry time should be that of earliest signature expiry`() {
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
            val rrset = RRset(RECORD, RRSIG, olderRrsig)

            rrset.signatureValidityPeriod?.endInclusive shouldBe olderRrsig.expire
        }
    }
}
