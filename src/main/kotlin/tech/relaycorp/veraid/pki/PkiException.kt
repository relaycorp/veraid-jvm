package tech.relaycorp.veraid.pki

import tech.relaycorp.veraid.VeraidException

/**
 * VeraId PKI exception.
 */
public class PkiException(message: String, cause: Throwable? = null) : VeraidException(
    message,
    cause,
)
