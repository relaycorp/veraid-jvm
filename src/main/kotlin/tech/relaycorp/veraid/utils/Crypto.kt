@file:JvmName("Crypto")

package tech.relaycorp.veraid.utils

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.MessageDigest

internal val BC_PROVIDER = BouncyCastleProvider()

internal enum class Hash(val hashName: String) {
    SHA_256("SHA-256"),
    SHA_384("SHA-384"),
    SHA_512("SHA-512"),
}

internal fun ByteArray.hash(hash: Hash): ByteArray {
    val digest = MessageDigest.getInstance(hash.hashName)
    return digest.digest(this)
}
