package tech.relaycorp.vera.utils

import java.math.BigInteger
import java.security.SecureRandom

internal fun generateRandomBigInteger(): BigInteger {
    val random = SecureRandom()
    return BigInteger(64, random)
}
