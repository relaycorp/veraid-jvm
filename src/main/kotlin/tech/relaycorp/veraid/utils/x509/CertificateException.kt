package tech.relaycorp.veraid.utils.x509

import tech.relaycorp.veraid.VeraException

/**
 * Vera PKI certificate exception.
 */
public class CertificateException(message: String, cause: Throwable? = null) :
    VeraException(message, cause)
