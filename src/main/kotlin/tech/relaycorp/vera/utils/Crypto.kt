package tech.relaycorp.vera.utils

import java.security.MessageDigest
import org.bouncycastle.jce.provider.BouncyCastleProvider

internal val BC_PROVIDER = BouncyCastleProvider()

internal fun getSHA256Digest(input: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(input)
}
