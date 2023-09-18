package tech.relaycorp.veraid.testing

import tech.relaycorp.veraid.utils.BC_PROVIDER
import java.security.KeyPair
import java.security.KeyPairGenerator

fun generateRSAKeyPair(modulus: Int = 2048): KeyPair {
    val keyGen = KeyPairGenerator.getInstance("RSA", BC_PROVIDER)
    keyGen.initialize(modulus)
    return keyGen.generateKeyPair()
}
