package tech.relaycorp.veraid.utils

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class CryptoTest {
    @Nested
    inner class ByteArrayHash {
        private val plaintext = "Hello world".toByteArray()

        @Test
        fun `SHA-256`() {
            val expectedDigest = "64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c"

            plaintext.hash(Hash.SHA_256) shouldBe expectedDigest.hexDecode()
        }

        @Test
        fun `SHA-384`() {
            val expectedDigest = "9203b0c4439fd1e6ae5878866337b7c532acd6d9260150c80318e8ab8c27ce3" +
                "30189f8df94fb890df1d298ff360627e1"

            plaintext.hash(Hash.SHA_384) shouldBe expectedDigest.hexDecode()
        }

        @Test
        fun `SHA-512`() {
            val expectedDigest = "b7f783baed8297f0db917462184ff4f08e69c2d5e5f79a942600f9725f58ce1" +
                "f29c18139bf80b06c0fff2bdd34738452ecf40c488c22a7e3d80cdf6f9c1c0d47"

            plaintext.hash(Hash.SHA_512) shouldBe expectedDigest.hexDecode()
        }

        private fun String.hexDecode(): ByteArray = chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
