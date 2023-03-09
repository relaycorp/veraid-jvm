package tech.relaycorp.veraid.utils.cms

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import tech.relaycorp.veraid.utils.Hash

internal val HASHING_ALGORITHM_OIDS = mapOf(
    Hash.SHA_256 to NISTObjectIdentifiers.id_sha256,
    Hash.SHA_384 to NISTObjectIdentifiers.id_sha384,
    Hash.SHA_512 to NISTObjectIdentifiers.id_sha512,
)
