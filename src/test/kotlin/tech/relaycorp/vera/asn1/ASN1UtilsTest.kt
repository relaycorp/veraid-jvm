package tech.relaycorp.vera.asn1

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.beInstanceOf
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1StreamParser
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DEROctetStringParser
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.DERVisibleString
import org.bouncycastle.asn1.DLSequenceParser
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

internal class ASN1UtilsTest {
    val visibleString = DERVisibleString("foo")
    val octetString = DEROctetString("bar".toByteArray())

    @Nested
    inner class MakeSequence {
        @Test
        fun `Values should be explicitly tagged by default`() {
            val sequence = ASN1Utils.makeSequence(listOf(visibleString, octetString))

            sequence shouldHaveSize 2

            val item1 = sequence.getObjectAt(0)
            item1 should beInstanceOf<DERVisibleString>()
            (item1 as DERVisibleString).string shouldBe visibleString.string

            val item2 = sequence.getObjectAt(1)
            item2 should beInstanceOf<DEROctetString>()
            (item2 as DEROctetString).octets.asList() shouldBe octetString.octets.asList()
        }

        @Test
        fun `Implicitly-tagged values should be supported`() {
            val sequence = ASN1Utils.makeSequence(listOf(visibleString, octetString), false)

            sequence shouldHaveSize 2

            val item1 = ASN1Utils.getVisibleString(sequence.getObjectAt(0) as ASN1TaggedObject)
            item1.string shouldBe visibleString.string

            val item2 = ASN1Utils.getOctetString(sequence.getObjectAt(1) as ASN1TaggedObject)
            val item2Serialization = (item2.loadedObject as DEROctetString).octets
            item2Serialization.asList() shouldBe octetString.octets.asList()
        }
    }

    @Nested
    inner class SerializeSequence {
        @Test
        fun `Values should be explicitly tagged by default`() {
            val serialization = ASN1Utils.serializeSequence(listOf(visibleString, octetString))

            val parser = ASN1StreamParser(serialization)
            val sequence = parser.readObject() as DLSequenceParser

            val item1 = sequence.readObject()
            item1 should beInstanceOf<DERVisibleString>()
            (item1 as DERVisibleString).string shouldBe visibleString.string

            val item2 = sequence.readObject()
            item2 should beInstanceOf<DEROctetStringParser>()
            item2 as DEROctetStringParser
            val item2Serialisation = (item2.loadedObject as DEROctetString).octets
            item2Serialisation.asList() shouldBe octetString.octets.asList()
        }

        @Test
        fun `Implicitly-tagged values should be supported`() {
            val serialization =
                ASN1Utils.serializeSequence(listOf(visibleString, octetString), false)

            val parser = ASN1StreamParser(serialization)
            val sequence =
                ASN1Sequence.getInstance(parser.readObject() as DLSequenceParser).toArray()

            val item1 = ASN1Utils.getVisibleString(sequence[0] as ASN1TaggedObject)
            item1.string shouldBe visibleString.string

            val item2 = ASN1Utils.getOctetString(sequence[1] as ASN1TaggedObject)
            val item2Serialization = (item2.loadedObject as DEROctetString).octets
            item2Serialization.asList() shouldBe octetString.octets.asList()
        }
    }

    @Nested
    inner class DeserializeSequence {
        @Test
        fun `Value should be refused if it's empty`() {
            val exception = shouldThrow<ASN1Exception> {
                ASN1Utils.deserializeHeterogeneousSequence(byteArrayOf())
            }

            exception.message shouldBe "Value is empty"
        }

        @Test
        fun `Value should be refused if it's not DER-encoded`() {
            val exception = shouldThrow<ASN1Exception> {
                ASN1Utils.deserializeHeterogeneousSequence("a".toByteArray())
            }

            exception.message shouldBe "Value is not DER-encoded"
        }

        @Test
        fun `Value should be refused if it's not a sequence`() {
            val serialization = DERVisibleString("hey").encoded

            val exception = shouldThrow<ASN1Exception> {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            }

            exception.message shouldBe "Value is not an ASN.1 sequence"
        }

        @Test
        fun `Explicitly tagged items should be deserialized with their corresponding types`() {
            val serialization = ASN1Utils.serializeSequence(listOf(visibleString, visibleString))

            val sequence = ASN1Utils.deserializeHomogeneousSequence<DERVisibleString>(serialization)

            sequence.size shouldBe 2
            val value1Deserialized = sequence.first()
            value1Deserialized shouldBe visibleString
            val value2Deserialized = sequence.last()
            value2Deserialized shouldBe visibleString
        }

        @Test
        fun `Explicitly tagged items with unexpected types should be refused`() {
            val serialization = ASN1Utils.serializeSequence(listOf(visibleString, octetString))

            val exception = shouldThrow<ASN1Exception> {
                ASN1Utils.deserializeHomogeneousSequence<DERVisibleString>(serialization)
            }

            exception.message shouldBe "Sequence contains an item of an unexpected type " +
                "(${octetString::class.java.simpleName})"
        }

        @Test
        fun `Implicitly tagged items should be deserialized with their corresponding types`() {
            val serialization =
                ASN1Utils.serializeSequence(listOf(visibleString, octetString), false)

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)

            sequence.size shouldBe 2
            val item1Serialization = ASN1Utils.getVisibleString(sequence[0]).octets
            item1Serialization.asList() shouldBe visibleString.octets.asList()
            val item2Serialization = ASN1Utils.getOctetString(sequence[1]).octets
            item2Serialization.asList() shouldBe octetString.octets.asList()
        }
    }

    @Nested
    inner class GetOID {
        private val oid = ASN1ObjectIdentifier("1.2.3.4.5")

        @Test
        fun `Invalid OID should be refused`() {
            val invalidImplicitlyTaggedOID = DERTaggedObject(false, 0, DERNull.INSTANCE)

            val exception = shouldThrow<ASN1Exception> {
                ASN1Utils.getOID(invalidImplicitlyTaggedOID)
            }

            exception.message shouldBe "Value is not an OID"
            exception.cause should beInstanceOf<IllegalArgumentException>()
        }

        @Test
        fun `Implicitly tagged OID should be accepted`() {
            val implicitlyTaggedOID = DERTaggedObject(false, 0, oid)

            val oidDeserialized = ASN1Utils.getOID(implicitlyTaggedOID)

            oidDeserialized shouldBe oid
        }
    }
}
