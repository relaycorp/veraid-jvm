import kotlinx.coroutines.delay
import org.bouncycastle.jce.provider.BouncyCastleProvider
import tech.relaycorp.veraid.dns.DnssecChain
import tech.relaycorp.veraid.pki.PkiException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec

private val BC_PROVIDER = BouncyCastleProvider()

fun generateRSAKeyPair(): KeyPair {
    val keyGen = KeyPairGenerator.getInstance("RSA", BC_PROVIDER)
    keyGen.initialize(2048)
    return keyGen.generateKeyPair()
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
 * Deserialise the RSA key pair from a private key serialization.
 */
@Throws(PkiException::class)
fun ByteArray.deserialiseRSAKeyPair(): KeyPair {
    val privateKey = this.deserialisePrivateKey("RSA") as RSAPrivateCrtKey
    val keyFactory = KeyFactory.getInstance("RSA", BC_PROVIDER)
    val publicKeySpec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
    val publicKey = keyFactory.generatePublic(publicKeySpec)
    return KeyPair(publicKey, privateKey)
}

suspend fun retrieveVeraidDnssecChain(orgName: String, maxRetries: Int): DnssecChain {
    var result: DnssecChain? = null
    var lastException: Throwable? = null
    for (i in 0 until maxRetries) {
        try {
            result = DnssecChain.retrieve(orgName)
            break
        } catch (exc: Throwable) {
            lastException = exc
            delay(100)
        }
    }
    return result ?: throw Exception("Failed after $maxRetries retries", lastException)
}
