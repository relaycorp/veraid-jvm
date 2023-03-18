@file:JvmName("Keys")

package tech.relaycorp.veraid.pki

import tech.relaycorp.veraid.KeyAlgorithm
import tech.relaycorp.veraid.OrganisationKeySpec
import tech.relaycorp.veraid.utils.BC_PROVIDER
import tech.relaycorp.veraid.utils.Hash
import tech.relaycorp.veraid.utils.hash
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

public enum class RsaModulus(internal val modulus: Int) {
    RSA_2048(2048),
    RSA_3072(3072),
    RSA_4096(4096),
    ;

    internal companion object {
        private val valueByModulus = RsaModulus.values().associateBy(RsaModulus::modulus)
        operator fun get(modulus: Int): RsaModulus? = valueByModulus[modulus]
    }
}

private val rsaModulusKeyAlgorithmMap: Map<RsaModulus, KeyAlgorithm> = mapOf(
    RsaModulus.RSA_2048 to KeyAlgorithm.RSA_2048,
    RsaModulus.RSA_3072 to KeyAlgorithm.RSA_3072,
    RsaModulus.RSA_4096 to KeyAlgorithm.RSA_4096,
)

private val rsaModulusHashMap: Map<RsaModulus, Hash> = mapOf(
    RsaModulus.RSA_2048 to Hash.SHA_256,
    RsaModulus.RSA_3072 to Hash.SHA_384,
    RsaModulus.RSA_4096 to Hash.SHA_512,
)

/**
 * Generate an RSA key pair.
 *
 * @param modulus The modulus
 */
public fun generateRSAKeyPair(modulus: RsaModulus = RsaModulus.RSA_2048): KeyPair {
    val keyGen = KeyPairGenerator.getInstance("RSA", BC_PROVIDER)
    keyGen.initialize(modulus.modulus)
    return keyGen.generateKeyPair()
}

internal val PublicKey.orgKeySpec: OrganisationKeySpec
    get() {
        if (this !is RSAPublicKey) {
            throw PkiException("Key type (${this.algorithm}) is unsupported")
        }
        val modulusRaw = this.modulus.bitLength()
        val modulusSanitised =
            RsaModulus[modulusRaw] ?: throw PkiException("RSA modulus $modulusRaw is unsupported")

        val keyAlgorithm = rsaModulusKeyAlgorithmMap[modulusSanitised]!!
        val hash = rsaModulusHashMap[modulusSanitised]!!
        val digest = this.encoded.hash(hash)
        val digestHex = Base64.getEncoder().encodeToString(digest)
        return OrganisationKeySpec(keyAlgorithm, digestHex)
    }

/**
 * Deserialise the RSA key pair from a private key serialization.
 */
@Throws(PkiException::class)
public fun ByteArray.deserialiseRSAKeyPair(): KeyPair {
    val privateKey = this.deserialisePrivateKey("RSA") as RSAPrivateCrtKey
    val keyFactory = KeyFactory.getInstance("RSA", BC_PROVIDER)
    val publicKeySpec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
    val publicKey = keyFactory.generatePublic(publicKeySpec)
    return KeyPair(publicKey, privateKey)
}

private fun ByteArray.deserialisePrivateKey(algorithm: String): PrivateKey {
    val privateKeySpec = PKCS8EncodedKeySpec(this)
    val keyFactory = KeyFactory.getInstance(algorithm, BC_PROVIDER)
    return try {
        keyFactory.generatePrivate(privateKeySpec)
    } catch (exc: InvalidKeySpecException) {
        throw PkiException("Value is not a valid $algorithm private key", exc)
    }
}

/**
 * Deserialise the RSA public key from a public key serialisation.
 */
public fun ByteArray.deserialiseRSAPublicKey(): RSAPublicKey =
    deserialisePublicKey("RSA") as RSAPublicKey

private fun ByteArray.deserialisePublicKey(algorithm: String): PublicKey {
    val spec = X509EncodedKeySpec(this)
    val factory = KeyFactory.getInstance(algorithm, BC_PROVIDER)
    return try {
        factory.generatePublic(spec)
    } catch (exc: InvalidKeySpecException) {
        throw PkiException("Value is not a valid $algorithm public key", exc)
    }
}
