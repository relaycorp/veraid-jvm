package tech.relaycorp.veraid

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.ZonedDateTime

class PeriodsTest {
    @Nested
    inner class DatePeriodToInstantPeriod {
        private val startDate = ZonedDateTime.now()
        private val endDate = startDate.plusSeconds(1)
        private val datePeriod = startDate..endDate

        @Test
        fun `Start date should be converted`() {
            datePeriod.toInstantPeriod().start shouldBe startDate.toInstant()
        }

        @Test
        fun `End date should be converted`() {
            datePeriod.toInstantPeriod().endInclusive shouldBe endDate.toInstant()
        }
    }
}
