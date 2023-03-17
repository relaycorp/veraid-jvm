package tech.relaycorp.veraid

import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERGeneralizedTime
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.utils.asn1.toGeneralizedTime
import java.time.ZoneOffset
import java.time.ZonedDateTime

class PeriodsTest {
    private val startDate = ZonedDateTime.now()
    private val endDate = startDate.plusSeconds(1)
    private val datePeriod = startDate..endDate

    @Nested
    inner class DatePeriodToInstantPeriod {
        @Test
        fun `Start date should be converted`() {
            datePeriod.toInstantPeriod().start shouldBe startDate.toInstant()
        }

        @Test
        fun `End date should be converted`() {
            datePeriod.toInstantPeriod().endInclusive shouldBe endDate.toInstant()
        }
    }

    @Nested
    inner class DatePeriodEncode {
        @Test
        fun `Start date should be output`() {
            val encoding = datePeriod.encode()

            val date =
                DERGeneralizedTime.getInstance(encoding.getObjectAt(0) as ASN1TaggedObject?, false)
            date shouldBe startDate.toGeneralizedTime()
        }

        @Test
        fun `End date should be output`() {
            val encoding = datePeriod.encode()

            val date =
                DERGeneralizedTime.getInstance(encoding.getObjectAt(1) as ASN1TaggedObject?, false)
            date shouldBe endDate.toGeneralizedTime()
        }
    }

    @Nested
    inner class DatePeriodIntersect {
        private val startDateUtc = startDate.withZoneSameInstant(ZoneOffset.UTC)
        private val endDateUtc = endDate.withZoneSameInstant(ZoneOffset.UTC)
        private val utcDatePeriod = startDateUtc..endDateUtc

        private val nonUtcZone = ZoneOffset.ofHours(1)

        @Test
        fun `Should return null if there's no intersection`() {
            val otherDatePeriod = endDateUtc.plusSeconds(1)..endDateUtc.plusSeconds(2)

            utcDatePeriod.intersect(otherDatePeriod) shouldBe null
        }

        @Test
        fun `Own start date should be converted to UTC`() {
            val ownStartDate = startDate.withZoneSameInstant(nonUtcZone)
            val ownDatePeriod = ownStartDate..endDateUtc
            val otherPeriod = startDateUtc.minusSeconds(1)..endDateUtc

            val intersection = ownDatePeriod.intersect(otherPeriod)

            intersection!!.start shouldBe startDateUtc
        }

        @Test
        fun `Own end date should be converted to UTC`() {
            val ownEndDate = endDate.withZoneSameInstant(nonUtcZone)
            val ownDatePeriod = startDateUtc..ownEndDate
            val otherPeriod = startDateUtc..endDateUtc.plusSeconds(1)

            val intersection = ownDatePeriod.intersect(otherPeriod)

            intersection!!.endInclusive shouldBe endDateUtc
        }

        @Test
        fun `Other start date should be converted to UTC`() {
            val otherStartDate = startDate.withZoneSameInstant(nonUtcZone)
            val otherDatePeriod = otherStartDate..endDateUtc
            val ownDatePeriod = startDateUtc.minusSeconds(1)..endDateUtc

            val intersection = ownDatePeriod.intersect(otherDatePeriod)

            intersection!!.start shouldBe startDateUtc
        }

        @Test
        fun `Other end date should be converted to UTC`() {
            val otherEndDate = endDate.withZoneSameInstant(nonUtcZone)
            val otherDatePeriod = startDateUtc..otherEndDate
            val ownDatePeriod = startDateUtc..endDateUtc.plusSeconds(1)

            val intersection = ownDatePeriod.intersect(otherDatePeriod)

            intersection!!.endInclusive shouldBe endDateUtc
        }
    }
}
