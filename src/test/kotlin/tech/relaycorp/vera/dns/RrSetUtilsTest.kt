package tech.relaycorp.vera.dns

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.RRset

class RrSetUtilsTest {
    @Nested
    inner class LatestSignatureInception {
        @Test
        fun `Unsigned RRset should result in null`() {
            val rrset = RRset(RECORD)

            rrset.latestSignatureInception shouldBe null
        }

        @Test
        fun `Inception time should be that of sole signature`() {
            val rrset = RRset(RECORD, RRSIG)

            rrset.latestSignatureInception shouldBe RRSIG.timeSigned
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

            rrset.latestSignatureInception shouldBe newerRrsig.timeSigned
        }
    }

    @Nested
    inner class EarliestSignatureExpiry {
        @Test
        fun `Unsigned RRset should result in null`() {
            val rrset = RRset(RECORD)

            rrset.earliestSignatureExpiry shouldBe null
        }

        @Test
        fun `Expiry time should be that of sole signature`() {
            val rrset = RRset(RECORD, RRSIG)

            rrset.earliestSignatureExpiry shouldBe RRSIG.expire
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

            rrset.earliestSignatureExpiry shouldBe olderRrsig.expire
        }
    }
}
