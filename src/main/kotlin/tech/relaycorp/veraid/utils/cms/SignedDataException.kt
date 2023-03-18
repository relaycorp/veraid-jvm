package tech.relaycorp.veraid.utils.cms

import tech.relaycorp.veraid.VeraidException

internal class SignedDataException(message: String, cause: Throwable? = null) :
    VeraidException(message, cause)
