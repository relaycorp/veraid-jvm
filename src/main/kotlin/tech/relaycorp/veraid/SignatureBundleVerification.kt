package tech.relaycorp.veraid

public data class SignatureBundleVerification(
    public val plaintext: ByteArray,
    public val member: Member,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SignatureBundleVerification

        if (!plaintext.contentEquals(other.plaintext)) return false
        return member == other.member
    }

    override fun hashCode(): Int {
        var result = plaintext.contentHashCode()
        result = 31 * result + member.hashCode()
        return result
    }
}
