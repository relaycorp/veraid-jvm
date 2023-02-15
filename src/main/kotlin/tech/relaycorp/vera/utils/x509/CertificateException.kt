package tech.relaycorp.vera.utils.x509

import tech.relaycorp.vera.VeraException

/**
 * Vera PKI certificate exception.
 */
public class CertificateException(message: String, cause: Throwable? = null) :
    VeraException(message, cause)
