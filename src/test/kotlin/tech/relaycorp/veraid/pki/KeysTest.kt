package tech.relaycorp.veraid.pki

import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.beInstanceOf
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException

class KeysTest {
    @Nested
    inner class GenerateRSAKeyPair {
        @Test
        fun `Key pair should be returned when a valid modulus is passed`() {
            val keyPair = generateRSAKeyPair(4096)

            keyPair.private should beInstanceOf<RSAPrivateKey>()
            (keyPair.private as RSAPrivateKey).modulus.bitLength() shouldBe 4096

            keyPair.public should beInstanceOf<RSAPublicKey>()
            (keyPair.public as RSAPublicKey).modulus.bitLength() shouldBe 4096
        }

        @Test
        fun `Modulus should be 2048 by default`() {
            val keyPair = generateRSAKeyPair()

            (keyPair.private as RSAPrivateKey).modulus.bitLength() shouldBe 2048

            (keyPair.public as RSAPublicKey).modulus.bitLength() shouldBe 2048
        }

        @Test
        fun `Modulus should be 2048 or greater`() {
            val exception = assertThrows<PkiException> {
                generateRSAKeyPair(2047)
            }
            exception.message shouldBe "Modulus should be at least 2048 (got 2047)"
        }

        @Test
        fun `BouncyCastle provider should be used`() {
            val keyPair = generateRSAKeyPair()

            keyPair.public should beInstanceOf<BCRSAPublicKey>()
            keyPair.private should beInstanceOf<BCRSAPrivateKey>()
        }
    }

    @Nested
    inner class DeserializeRSAKeyPair {
        @Test
        fun `Deserialize invalid key`() {
            val exception =
                assertThrows<PkiException> { "s".toByteArray().deserializeRSAKeyPair() }

            exception.message shouldBe "Value is not a valid RSA private key"
            exception.cause should beInstanceOf<InvalidKeySpecException>()
        }

        @Test
        fun `Deserialize valid private key`() {
            val keyPair = generateRSAKeyPair()
            val privateKeySerialized = keyPair.private.encoded

            val keyPairDeserialized = privateKeySerialized.deserializeRSAKeyPair()

            keyPairDeserialized.private shouldBe keyPair.private
            keyPairDeserialized.public shouldBe keyPair.public
        }

        @Test
        fun `BouncyCastle provider should be used`() {
            val keyPair = generateRSAKeyPair()
            val privateKeySerialized = keyPair.private.encoded

            val keyPairDeserialized = privateKeySerialized.deserializeRSAKeyPair()

            keyPairDeserialized.public should beInstanceOf<BCRSAPublicKey>()
            keyPairDeserialized.private should beInstanceOf<BCRSAPrivateKey>()
        }
    }

    @Nested
    inner class DeserializeRSAPublicKey {
        @Test
        fun `Deserialize invalid key`() {
            val exception =
                assertThrows<PkiException> { "s".toByteArray().deserializeRSAPublicKey() }

            exception.message shouldBe "Value is not a valid RSA public key"
            exception.cause should beInstanceOf<InvalidKeySpecException>()
        }

        @Test
        fun `Deserialize valid key`() {
            val keyPair = generateRSAKeyPair()
            val publicKeySerialized = keyPair.public.encoded

            val publicKeyDeserialized = publicKeySerialized.deserializeRSAPublicKey()

            publicKeyDeserialized shouldBe keyPair.public
        }

        @Test
        fun `BouncyCastle provider should be used`() {
            val keyPair = generateRSAKeyPair()
            val publicKeySerialized = keyPair.public.encoded

            val publicKeyDeserialized = publicKeySerialized.deserializeRSAPublicKey()

            publicKeyDeserialized should beInstanceOf<BCRSAPublicKey>()
        }
    }
}
