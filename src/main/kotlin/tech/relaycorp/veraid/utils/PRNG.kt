@file:JvmName("PRNG")

package tech.relaycorp.veraid.utils

import java.math.BigInteger
import java.security.SecureRandom

internal fun generateRandomBigInteger(): BigInteger {
    val random = SecureRandom()
    return BigInteger(64, random)
}
