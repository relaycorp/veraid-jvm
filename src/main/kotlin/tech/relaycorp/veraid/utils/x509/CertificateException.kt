package tech.relaycorp.veraid.utils.x509

import tech.relaycorp.veraid.VeraidException

/**
 * VeraId PKI certificate exception.
 */
public class CertificateException(message: String, cause: Throwable? = null) :
    VeraidException(message, cause)
