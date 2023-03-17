import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.veraid.SignatureBundle
import tech.relaycorp.veraid.SignatureException
import tech.relaycorp.veraid.dns.VeraDnssecChain
import tech.relaycorp.veraid.pki.MemberCertificate
import tech.relaycorp.veraid.pki.MemberIdBundle
import tech.relaycorp.veraid.pki.OrgCertificate
import tech.relaycorp.veraid.pki.generateRSAKeyPair
import java.time.ZonedDateTime

class MainTest {
    private val now = ZonedDateTime.now()
    private val expiryDate = now.plusSeconds(60)

    private val orgCertificate = OrgCertificate.selfIssue(
        TestStubs.ORG_NAME,
        TestStubs.ORG_KEY_PAIR,
        expiryDate,
        now,
    )

    private val memberCertificate = MemberCertificate.issue(
        TestStubs.USER_NAME,
        TestStubs.MEMBER_KEY_PAIR.public,
        orgCertificate,
        TestStubs.ORG_KEY_PAIR.private,
        expiryDate,
        now,
    )

    private lateinit var veraDnssecChain: VeraDnssecChain

    @BeforeAll
    fun retrieveVeraDnssecChain() = runBlocking {
        veraDnssecChain = retrieveVeraidDnssecChain(TestStubs.ORG_NAME, 3)
    }

    @Test
    fun validSignatureBundle() = runBlocking {
        val memberIdBundle = MemberIdBundle(veraDnssecChain, orgCertificate, memberCertificate)
        val signatureBundle = SignatureBundle.generate(
            TestStubs.PLAINTEXT,
            TestStubs.TEST_SERVICE_OID,
            memberIdBundle,
            TestStubs.MEMBER_KEY_PAIR.private,
            expiryDate,
            now,
        )

        val member = signatureBundle.verify(TestStubs.PLAINTEXT, TestStubs.TEST_SERVICE_OID)

        assert(member.orgName == TestStubs.ORG_NAME)
        assert(member.userName == TestStubs.USER_NAME)
    }

    @Test
    fun invalidSignatureBundle(): Unit = runBlocking {
        val otherMemberKeyPair = generateRSAKeyPair()
        val memberIdBundle = MemberIdBundle(veraDnssecChain, orgCertificate, memberCertificate)
        val signatureBundle = SignatureBundle.generate(
            TestStubs.PLAINTEXT,
            TestStubs.TEST_SERVICE_OID,
            memberIdBundle,
            otherMemberKeyPair.private,
            expiryDate,
            now,
        )

        assertThrows<SignatureException> {
            signatureBundle.verify(TestStubs.PLAINTEXT, TestStubs.TEST_SERVICE_OID)
        }
    }

    @Test
    fun differentService(): Unit = runBlocking {
        val memberIdBundle = MemberIdBundle(veraDnssecChain, orgCertificate, memberCertificate)
        val signatureBundle = SignatureBundle.generate(
            TestStubs.PLAINTEXT,
            TestStubs.TEST_SERVICE_OID,
            memberIdBundle,
            TestStubs.MEMBER_KEY_PAIR.private,
            expiryDate,
            now,
        )

        val otherServiceOid = "${TestStubs.TEST_SERVICE_OID}.1"
        assertThrows<SignatureException> {
            signatureBundle.verify(TestStubs.PLAINTEXT, otherServiceOid)
        }
    }
}
