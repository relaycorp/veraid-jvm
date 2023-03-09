package tech.relaycorp.veraid.utils.cms

import tech.relaycorp.veraid.VeraException

internal class SignedDataException(message: String, cause: Throwable? = null) :
    VeraException(message, cause)
