package tech.relaycorp.veraid.pki

import tech.relaycorp.veraid.VeraException

/**
 * Vera PKI exception.
 */
public class PkiException(message: String, cause: Throwable? = null) : VeraException(message, cause)
