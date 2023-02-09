package tech.relaycorp.vera

public abstract class VeraException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
