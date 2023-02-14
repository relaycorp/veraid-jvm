package tech.relaycorp.vera.utils

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class TimeTest {
    @Nested
    inner class IntersectInstantRange {
        @Test
        fun `Non-overlapping ranges should result in null`() {
            (1..2).intersect(3..4) shouldBe null
        }

        @Suppress("EmptyRange")
        @Test
        fun `Reversed range should result in null`() {
            (5..1).intersect(2..4) shouldBe null
            (1..5).intersect(4..2) shouldBe null
        }

        @Test
        fun `The highest of the two start values should be taken`() {
            (1..5).intersect(2..5)?.start shouldBe 2
            (2..5).intersect(1..5)?.start shouldBe 2
        }

        @Test
        fun `The lowest of the two end values should be taken`() {
            (1..4).intersect(1..5)?.endInclusive shouldBe 4
            (1..5).intersect(1..4)?.endInclusive shouldBe 4
        }
    }
}
