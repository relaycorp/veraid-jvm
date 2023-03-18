package tech.relaycorp.veraid.dns

import tech.relaycorp.veraid.VeraidException

/**
 * Exception representing an invalid/malformed [DnssecChain].
 */
public class InvalidChainException(message: String, cause: Throwable? = null) :
    VeraidException(message, cause)
