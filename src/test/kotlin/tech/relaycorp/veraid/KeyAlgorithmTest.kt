package tech.relaycorp.veraid

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource

internal class KeyAlgorithmTest {
    @Nested
    inner class Get {
        @ParameterizedTest
        @EnumSource(KeyAlgorithm::class)
        fun `Value should be returned for existing id`(algorithm: KeyAlgorithm) {
            val value = KeyAlgorithm[algorithm.typeId]

            value shouldBe algorithm
        }

        @Test
        fun `Non-existing value should result in null`() {
            KeyAlgorithm[0] shouldBe null
        }
    }
}
