package tech.relaycorp.veraid.utils

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.MessageDigest

internal val BC_PROVIDER = BouncyCastleProvider()

internal fun getSHA256Digest(input: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(input)
}
