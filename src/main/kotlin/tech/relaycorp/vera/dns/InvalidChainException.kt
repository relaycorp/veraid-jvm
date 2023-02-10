package tech.relaycorp.vera.dns

import tech.relaycorp.vera.VeraException

public class InvalidChainException(message: String, cause: Throwable? = null) :
    VeraException(message, cause)
