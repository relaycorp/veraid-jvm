package tech.relaycorp.vera.pki

import tech.relaycorp.vera.VeraException

/**
 * Vera PKI exception.
 */
public class PKIException(message: String, cause: Throwable? = null) : VeraException(message, cause)
