package tech.relaycorp.veraid.dns

import tech.relaycorp.veraid.VeraidException

public class InvalidChainException(message: String, cause: Throwable? = null) :
    VeraidException(message, cause)
