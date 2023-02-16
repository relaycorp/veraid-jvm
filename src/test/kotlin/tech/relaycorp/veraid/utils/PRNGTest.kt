package tech.relaycorp.veraid.utils

import io.kotest.matchers.ints.shouldBeInRange
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.RepeatedTest

class PRNGTest {
    @Nested
    inner class GenerateRandomBigInteger {
        @RepeatedTest(8) // Because the bitLength of the value is variable
        fun `Output should be 64 bit unsigned number`() {
            val value = generateRandomBigInteger()

            value.signum() shouldBe 1
            value.bitLength() shouldBeInRange 48..64
        }
    }
}
