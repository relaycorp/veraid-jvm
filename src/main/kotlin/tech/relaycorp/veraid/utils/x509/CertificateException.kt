package tech.relaycorp.veraid.utils.x509

import tech.relaycorp.veraid.VeraidException

/**
 * VeraId-agnostic certificate exception.
 */
internal class CertificateException(message: String, cause: Throwable? = null) :
    VeraidException(message, cause)
