package tech.relaycorp.veraid.pki

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import org.bouncycastle.util.encoders.Base64
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.KeyAlgorithm
import tech.relaycorp.veraid.testing.generateRSAKeyPair
import tech.relaycorp.veraid.utils.BC_PROVIDER
import tech.relaycorp.veraid.utils.Hash
import tech.relaycorp.veraid.utils.hash
import java.security.KeyPairGenerator

class KeysTest {
    @Nested
    inner class OrgKeySpec {
        @Test
        fun `RSA-2048 should use SHA-256`() {
            val publicKey = generateRSAKeyPair().public

            val spec = publicKey.orgKeySpec

            spec.id shouldBe publicKey.encoded.hash(Hash.SHA_256).toBase64()
            spec.algorithm shouldBe KeyAlgorithm.RSA_2048
        }

        @Test
        fun `RSA-3072 should use SHA-384`() {
            val publicKey = generateRSAKeyPair(3072).public

            val spec = publicKey.orgKeySpec

            spec.id shouldBe publicKey.encoded.hash(Hash.SHA_384).toBase64()
            spec.algorithm shouldBe KeyAlgorithm.RSA_3072
        }

        @Test
        fun `RSA-4096 should use SHA-512`() {
            val publicKey = generateRSAKeyPair(4096).public

            val spec = publicKey.orgKeySpec

            spec.id shouldBe publicKey.encoded.hash(Hash.SHA_512).toBase64()
            spec.algorithm shouldBe KeyAlgorithm.RSA_4096
        }

        @Test
        fun `Unsupported RSA modulus should be refused`() {
            val keyGen = KeyPairGenerator.getInstance("RSA", BC_PROVIDER)
            val keySize = 1024
            keyGen.initialize(keySize)
            val rsa1024PublicKey = keyGen.genKeyPair().public

            val exception = shouldThrow<PkiException> { rsa1024PublicKey.orgKeySpec }

            exception.message shouldBe "RSA modulus $keySize is unsupported"
        }

        @Test
        fun `Non-RSA key should be refused`() {
            val keyGen = KeyPairGenerator.getInstance("EC", BC_PROVIDER)
            keyGen.initialize(256)
            val p256PublicKey = keyGen.genKeyPair().public

            val exception = shouldThrow<PkiException> { p256PublicKey.orgKeySpec }

            exception.message shouldBe "Key type (EC) is unsupported"
        }

        private fun ByteArray.toBase64() = Base64.toBase64String(this)
    }
}
