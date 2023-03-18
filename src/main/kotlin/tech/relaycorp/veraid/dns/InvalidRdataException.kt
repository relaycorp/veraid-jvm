package tech.relaycorp.veraid.dns

import tech.relaycorp.veraid.VeraidException

/**
 * Exception representing an invalid/malformed [RdataFieldSet].
 */
public class InvalidRdataException(message: String) : VeraidException(message)
