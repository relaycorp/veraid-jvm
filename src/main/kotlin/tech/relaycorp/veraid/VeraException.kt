package tech.relaycorp.veraid

public abstract class VeraException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
