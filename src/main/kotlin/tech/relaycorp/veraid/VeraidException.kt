package tech.relaycorp.veraid

/**
 * Base class for all VeraId exceptions.
 */
public abstract class VeraidException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
