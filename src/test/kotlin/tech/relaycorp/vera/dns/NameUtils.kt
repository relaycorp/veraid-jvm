package tech.relaycorp.vera.dns

import org.xbill.DNS.Name

internal fun Name.makeSubdomain(subdomain: String): Name =
    Name.concatenate(Name.fromString(subdomain), this)
