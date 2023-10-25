package tech.relaycorp.veraid

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class SignatureBundleVerificationTest {
    val verification = SignatureBundleVerification(
        "plaintext".toByteArray(),
        Member(ORG_NAME, USER_NAME),
    )

    @Nested
    inner class Equals {
        @Test
        @Suppress("ReplaceCallWithBinaryOperator")
        fun `The same object should equal`() {
            verification.equals(verification) shouldBe true
        }

        @Test
        fun `Null should not equal`() {
            verification.equals(null) shouldBe false
        }

        @Test
        fun `Different class should not equal`() {
            verification.equals("foo") shouldBe false
        }

        @Test
        fun `Different plaintext should not equal`() {
            verification shouldNotBe verification.copy(plaintext = "foo".toByteArray())
        }

        @Test
        fun `Different member should not equal`() {
            val differentMember = verification.member.copy(orgName = "not-$ORG_NAME")

            verification shouldNotBe verification.copy(member = differentMember)
        }
    }

    @Test
    fun `Hashcode should compine member and plaintext`() {
        val constant = 31
        val expectedHashCode =
            verification.member.hashCode() + constant * verification.plaintext.contentHashCode()

        verification.hashCode() shouldBe expectedHashCode
    }
}
