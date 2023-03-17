import tech.relaycorp.veraid.pki.deserializeRSAKeyPair
import tech.relaycorp.veraid.pki.generateRSAKeyPair

object TestStubs {
    const val ORG_NAME = "lib-testing.veraid.net"

    private val ORG_PRIVATE_KEY =
        TestStubs::class.java.getResourceAsStream("/organisationPrivateKey.der")!!.readAllBytes()
    val ORG_KEY_PAIR = ORG_PRIVATE_KEY.deserializeRSAKeyPair()

    const val USER_NAME = "alice"
    val MEMBER_KEY_PAIR = generateRSAKeyPair()

    val PLAINTEXT = "This is the plaintext".toByteArray()

    const val TEST_SERVICE_OID = "1.3.6.1.4.1.58708.1.1"
}
