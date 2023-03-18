package tech.relaycorp.veraid.dns

import tech.relaycorp.veraid.VeraidException

/**
 * Exception representing a DNS- or DNSSEC-related error.
 */
public class DnsException(message: String) : VeraidException(message)
