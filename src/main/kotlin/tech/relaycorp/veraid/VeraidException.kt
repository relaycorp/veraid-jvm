package tech.relaycorp.veraid

public abstract class VeraidException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
