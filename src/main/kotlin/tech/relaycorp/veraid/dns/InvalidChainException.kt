package tech.relaycorp.veraid.dns

import tech.relaycorp.veraid.VeraException

public class InvalidChainException(message: String, cause: Throwable? = null) :
    VeraException(message, cause)
