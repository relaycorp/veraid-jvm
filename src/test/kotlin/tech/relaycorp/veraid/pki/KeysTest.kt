package tech.relaycorp.veraid.pki

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.beInstanceOf
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.veraid.KeyAlgorithm
import tech.relaycorp.veraid.utils.BC_PROVIDER
import tech.relaycorp.veraid.utils.Hash
import tech.relaycorp.veraid.utils.hash
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.util.Base64

class KeysTest {
    @Nested
    inner class GenerateRSAKeyPair {
        @Test
        fun `Key pair should be returned when a valid modulus is passed`() {
            val keyPair = generateRSAKeyPair(RsaModulus.RSA_4096)

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
                shouldThrow<PkiException> { "s".toByteArray().deserializeRSAKeyPair() }

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
                shouldThrow<PkiException> { "s".toByteArray().deserializeRSAPublicKey() }

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
            val publicKey = generateRSAKeyPair(RsaModulus.RSA_3072).public

            val spec = publicKey.orgKeySpec

            spec.id shouldBe publicKey.encoded.hash(Hash.SHA_384).toBase64()
            spec.algorithm shouldBe KeyAlgorithm.RSA_3072
        }

        @Test
        fun `RSA-4096 should use SHA-512`() {
            val publicKey = generateRSAKeyPair(RsaModulus.RSA_4096).public

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

        private fun ByteArray.toBase64() = Base64.getEncoder().encodeToString(this)
    }
}
