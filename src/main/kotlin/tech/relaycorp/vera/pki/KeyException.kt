package tech.relaycorp.vera.pki

import tech.relaycorp.vera.VeraException

/**
 * Exception while generating a cryptographic key.
 */
public class KeyException(message: String, cause: Throwable? = null) : VeraException(message, cause)
