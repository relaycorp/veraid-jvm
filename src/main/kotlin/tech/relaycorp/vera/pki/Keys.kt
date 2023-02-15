@file:JvmName("Keys")

package tech.relaycorp.vera.pki

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
import tech.relaycorp.vera.utils.BC_PROVIDER

private const val DEFAULT_RSA_KEY_MODULUS = 2048
private const val MIN_RSA_KEY_MODULUS = 2048

/**
 * Generate an RSA key pair.
 *
 * @param modulus The modulus
 * @throws KeyException If `modulus` is less than 2048
 */
@Throws(KeyException::class)
public fun generateRSAKeyPair(modulus: Int = DEFAULT_RSA_KEY_MODULUS): KeyPair {
    if (modulus < MIN_RSA_KEY_MODULUS) {
        throw KeyException("Modulus should be at least $MIN_RSA_KEY_MODULUS (got $modulus)")
    }
    val keyGen = KeyPairGenerator.getInstance("RSA", BC_PROVIDER)
    keyGen.initialize(modulus)
    return keyGen.generateKeyPair()
}

/**
 * Deserialize the RSA key pair from a private key serialization.
 */
@Throws(KeyException::class)
public fun ByteArray.deserializeRSAKeyPair(): KeyPair {
    val privateKey = this.deserializePrivateKey("RSA") as RSAPrivateCrtKey
    val keyFactory = KeyFactory.getInstance("RSA", BC_PROVIDER)
    val publicKeySpec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
    val publicKey = keyFactory.generatePublic(publicKeySpec)
    return KeyPair(publicKey, privateKey)
}

private fun ByteArray.deserializePrivateKey(algorithm: String): PrivateKey {
    val privateKeySpec = PKCS8EncodedKeySpec(this)
    val keyFactory = KeyFactory.getInstance(algorithm, BC_PROVIDER)
    return try {
        keyFactory.generatePrivate(privateKeySpec)
    } catch (exc: InvalidKeySpecException) {
        throw KeyException("Value is not a valid $algorithm private key", exc)
    }
}

public fun ByteArray.deserializeRSAPublicKey(): RSAPublicKey =
    deserializePublicKey("RSA") as RSAPublicKey

private fun ByteArray.deserializePublicKey(algorithm: String): PublicKey {
    val spec = X509EncodedKeySpec(this)
    val factory = KeyFactory.getInstance(algorithm, BC_PROVIDER)
    return try {
        factory.generatePublic(spec)
    } catch (exc: InvalidKeySpecException) {
        throw KeyException("Value is not a valid $algorithm public key", exc)
    }
}
