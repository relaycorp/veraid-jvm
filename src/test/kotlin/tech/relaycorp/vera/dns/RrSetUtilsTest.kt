package tech.relaycorp.vera.dns

import io.kotest.matchers.shouldBe
import java.time.Instant
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.xbill.DNS.DClass
import org.xbill.DNS.Name
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.RRset
import org.xbill.DNS.TXTRecord

class RrSetUtilsTest {
    private val record = TXTRecord(
        Name.fromString(DnsStubs.DOMAIN_NAME),
        DClass.IN,
        42,
        "foo"
    )

    private val now: Instant = Instant.now()
    private val signature = RRSIGRecord(
        record.name,
        record.dClass,
        record.ttl,
        record.type,
        3,
        record.ttl,
        now,
        now.plusSeconds(60),
        42,
        Name.root,
        "the signature".toByteArray()
    )

    @Nested
    inner class LatestSignatureInception {
        @Test
        fun `Unsigned RRset should result in null`() {
            val rrset = RRset(record)

            rrset.latestSignatureInception shouldBe null
        }

        @Test
        fun `Inception time should be that of sole signature`() {
            val rrset = RRset(record, signature)

            rrset.latestSignatureInception shouldBe signature.timeSigned
        }

        @Test
        fun `Inception time should be that of latest signature inceptions`() {
            val newerSignature = RRSIGRecord(
                signature.name,
                signature.dClass,
                signature.ttl,
                signature.typeCovered,
                signature.algorithm,
                signature.origTTL,
                signature.timeSigned.plusSeconds(1),
                signature.expire,
                signature.footprint,
                signature.signer,
                signature.signature
            )
            val rrset = RRset(record, signature, newerSignature)

            rrset.latestSignatureInception shouldBe newerSignature.timeSigned
        }
    }

    @Nested
    inner class EarliestSignatureExpiry {
        @Test
        fun `Unsigned RRset should result in null`() {
            val rrset = RRset(record)

            rrset.earliestSignatureExpiry shouldBe null
        }

        @Test
        fun `Expiry time should be that of sole signature`() {
            val rrset = RRset(record, signature)

            rrset.earliestSignatureExpiry shouldBe signature.expire
        }

        @Test
        fun `Expiry time should be that of earliest signature expiry`() {
            val olderSignature = RRSIGRecord(
                signature.name,
                signature.dClass,
                signature.ttl,
                signature.typeCovered,
                signature.algorithm,
                signature.origTTL,
                signature.timeSigned,
                signature.expire.minusSeconds(1),
                signature.footprint,
                signature.signer,
                signature.signature
            )
            val rrset = RRset(record, signature, olderSignature)

            rrset.earliestSignatureExpiry shouldBe olderSignature.expire
        }
    }
}
