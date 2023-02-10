package tech.relaycorp.vera

internal enum class KeyAlgorithm(val typeId: Int) {
    RSA_2048(1),
    RSA_3072(2),
    RSA_4096(3),
}
