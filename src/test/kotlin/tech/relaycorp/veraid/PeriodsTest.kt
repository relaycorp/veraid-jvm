package tech.relaycorp.veraid

import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERGeneralizedTime
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.utils.asn1.ASN1Utils
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
            date shouldBe ASN1Utils.derEncodeUTCDate(startDate)
        }

        @Test
        fun `End date should be output`() {
            val encoding = datePeriod.encode()

            val date =
                DERGeneralizedTime.getInstance(encoding.getObjectAt(1) as ASN1TaggedObject?, false)
            date shouldBe ASN1Utils.derEncodeUTCDate(endDate)
        }
    }
}
