package tech.relaycorp.veraid

/**
 * Exception representing an invalid/malformed [SignatureBundle].
 */
public class SignatureException(message: String, cause: Throwable? = null) :
    VeraidException(message, cause)
