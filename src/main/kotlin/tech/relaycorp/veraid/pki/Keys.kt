@file:JvmName("Keys")

package tech.relaycorp.veraid.pki

import org.bouncycastle.util.encoders.Base64
import tech.relaycorp.veraid.KeyAlgorithm
import tech.relaycorp.veraid.OrganisationKeySpec
import tech.relaycorp.veraid.utils.Hash
import tech.relaycorp.veraid.utils.hash
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey

private val SUPPORTED_RSA_MODULI = setOf(2048, 3072, 4096)

private val rsaModulusKeyAlgorithmMap: Map<Int, KeyAlgorithm> = mapOf(
    2048 to KeyAlgorithm.RSA_2048,
    3072 to KeyAlgorithm.RSA_3072,
    4096 to KeyAlgorithm.RSA_4096,
)

private val rsaModulusHashMap: Map<Int, Hash> = mapOf(
    2048 to Hash.SHA_256,
    3072 to Hash.SHA_384,
    4096 to Hash.SHA_512,
)

internal val PublicKey.orgKeySpec: OrganisationKeySpec
    get() {
        if (this !is RSAPublicKey) {
            throw PkiException("Key type (${this.algorithm}) is unsupported")
        }
        val modulus = this.modulus.bitLength()
        if (modulus !in SUPPORTED_RSA_MODULI) {
            throw PkiException("RSA modulus $modulus is unsupported")
        }

        val keyAlgorithm = rsaModulusKeyAlgorithmMap[modulus]!!
        val hash = rsaModulusHashMap[modulus]!!
        val digest = this.encoded.hash(hash)
        val digestHex = Base64.toBase64String(digest)
        return OrganisationKeySpec(keyAlgorithm, digestHex)
    }
