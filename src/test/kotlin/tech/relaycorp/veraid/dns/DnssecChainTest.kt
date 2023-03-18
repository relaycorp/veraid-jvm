package tech.relaycorp.veraid.dns

import com.nhaarman.mockitokotlin2.spy
import com.nhaarman.mockitokotlin2.verify
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.beInstanceOf
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSet
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.Isolated
import org.xbill.DNS.Message
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.Type
import org.xbill.DNS.WireParseException
import tech.relaycorp.veraid.KeyAlgorithm
import tech.relaycorp.veraid.ORG_KEY_SPEC
import tech.relaycorp.veraid.ORG_NAME
import tech.relaycorp.veraid.SERVICE_OID
import tech.relaycorp.veraid.utils.asn1.parseDer
import tech.relaycorp.veraid.utils.asn1.toDlTaggedObject
import java.lang.IllegalStateException
import java.time.ZonedDateTime
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

data class RetrieverCallArgs(
    val domainName: String,
    val recordType: String,
    val resolverHost: String,
)

class DnssecChainTest {
    @Nested
    inner class Constructor {
        @Test
        fun `Organisation name should be stored`() {
            val chain = DnssecChain(ORG_NAME, emptyList())

            chain.orgName shouldBe ORG_NAME
        }

        @Test
        fun `VeraId TXT subdomain should be stored`() {
            val chain = DnssecChain(ORG_NAME, emptyList())

            chain.domainName shouldBe "_veraid.$DOMAIN_NAME"
        }
    }

    @Nested
    inner class Retrieve {
        private val originalChainRetriever = DnssecChain.chainRetriever
        private var retrieverCallArgs: RetrieverCallArgs? = null

        @AfterEach
        fun restoreRetriever() {
            DnssecChain.chainRetriever = originalChainRetriever
        }

        @BeforeEach
        fun resetRetrieverCallArgs() {
            retrieverCallArgs = null
        }

        @Test
        fun `Subdomain _vera of specified domain should be queried`() = runTest {
            DnssecChain.chainRetriever = makeRetriever()

            DnssecChain.retrieve(ORG_NAME)

            retrieverCallArgs?.domainName shouldBe "_veraid.$DOMAIN_NAME"
        }

        @Test
        fun `Trailing dot should be dropped from organisation name if present`() = runTest {
            DnssecChain.chainRetriever = makeRetriever()

            DnssecChain.retrieve(DOMAIN_NAME)

            retrieverCallArgs?.domainName shouldBe "_veraid.$DOMAIN_NAME"
        }

        @Test
        fun `TXT record type should be queried`() = runTest {
            DnssecChain.chainRetriever = makeRetriever()

            DnssecChain.retrieve(ORG_NAME)

            retrieverCallArgs?.recordType shouldBe "TXT"
        }

        @Test
        fun `Cloudflare DNS resolver should be used by default`() = runTest {
            DnssecChain.chainRetriever = makeRetriever()

            DnssecChain.retrieve(ORG_NAME)

            retrieverCallArgs?.resolverHost shouldBe "1.1.1.1"
        }

        @Test
        fun `Another DNS resolver should be used if explicitly set`() = runTest {
            val resolverHost = "1.2.3.4"
            DnssecChain.chainRetriever = makeRetriever()

            DnssecChain.retrieve(ORG_NAME, resolverHost)

            retrieverCallArgs?.resolverHost shouldBe resolverHost
        }

        @Test
        fun `Responses should be stored in chain`() = runTest {
            val response = Message()
            response.header.id = 42
            DnssecChain.chainRetriever = makeRetriever(listOf(response))

            val chain = DnssecChain.retrieve(ORG_NAME)

            chain.responses shouldHaveSize 1
            chain.responses.first() shouldBe response
        }

        @Test
        fun `Org name should be stored in chain`() = runTest {
            DnssecChain.chainRetriever = makeRetriever()

            val chain = DnssecChain.retrieve(ORG_NAME)

            chain.orgName shouldBe ORG_NAME
        }

        private fun makeRetriever(responses: List<Message> = emptyList()): ChainRetriever =
            { domainName, recordType, resolverHostName ->
                retrieverCallArgs = RetrieverCallArgs(domainName, recordType, resolverHostName)
                BaseDnssecChain(DOMAIN_NAME, "TXT", responses)
            }
    }

    @Nested
    inner class Serialise {
        @Test
        fun `Responses should be wrapped in an explicitly tagged SET`() {
            val response1 = Message()
            val response2 = Message(response1.header.id + 1)
            val chain = DnssecChain(ORG_NAME, listOf(response1, response2))

            val serialisation = chain.serialise()

            val asn1Set = parseDer(serialisation)
            val set = ASN1Set.getInstance(asn1Set)
            set shouldHaveSize 2
            set.first() should beInstanceOf<DEROctetString>()
            (set.first() as DEROctetString).octets shouldBe response1.toWire()
            set.last() should beInstanceOf<DEROctetString>()
            (set.last() as DEROctetString).octets shouldBe response2.toWire()
        }
    }

    @Nested
    inner class Encode {
        @Test
        fun `Responses should be wrapped in an explicitly tagged SET`() {
            val response1 = Message()
            val response2 = Message(response1.header.id + 1)
            val chain = DnssecChain(ORG_NAME, listOf(response1, response2))

            val asn1Set = chain.encode()

            val set = ASN1Set.getInstance(asn1Set)
            set shouldHaveSize 2
            set.first() should beInstanceOf<DEROctetString>()
            (set.first() as DEROctetString).octets shouldBe response1.toWire()
            set.last() should beInstanceOf<DEROctetString>()
            (set.last() as DEROctetString).octets shouldBe response2.toWire()
        }
    }

    @Nested
    inner class DecodeTaggedObject {
        @Test
        fun `Encoding should be a SET`() {
            val malformedSet = DERNull.INSTANCE.toDlTaggedObject(false)

            val exception = shouldThrow<InvalidChainException> {
                DnssecChain.decode(ORG_NAME, malformedSet)
            }

            exception.message shouldBe "Chain is not an implicitly-tagged SET"
            exception.cause should beInstanceOf<IllegalStateException>()
        }

        @Test
        fun `Encoding should be implicitly-tagged`() {
            val malformedSet = DERSet().toDlTaggedObject(true)

            val exception = shouldThrow<InvalidChainException> {
                DnssecChain.decode(ORG_NAME, malformedSet)
            }

            exception.message shouldBe "Chain is not an implicitly-tagged SET"
            exception.cause should beInstanceOf<IllegalStateException>()
        }

        @Test
        fun `Chain should be initialised from valid SET`() {
            val chain = DnssecChain(ORG_NAME, listOf(RECORD.makeResponse()))
            val encoding = parseDer(chain.serialise()) as ASN1Set

            val chainDecoded = DnssecChain.decode(ORG_NAME, encoding)

            chainDecoded.orgName shouldBe ORG_NAME
            chainDecoded.responses shouldHaveSize 1
        }
    }

    @Nested
    inner class DecodeSet {
        @Test
        fun `Empty set should be supported`() {
            val set = DERSet()

            val chain = DnssecChain.decode(ORG_NAME, set)

            chain.responses shouldHaveSize 0
        }

        @Test
        fun `Malformed response should be refused`() {
            val vector = ASN1EncodableVector(1)
            vector.add(DEROctetString("malformed message".toByteArray()))
            val invalidSet = DERSet(vector)

            val exception = shouldThrow<InvalidChainException> {
                DnssecChain.decode(ORG_NAME, invalidSet)
            }

            exception.message shouldBe "Chain contains a malformed DNS message"
            exception.cause should beInstanceOf<WireParseException>()
        }

        @Test
        fun `Non-OCTET STRING item should be refused`() {
            val vector = ASN1EncodableVector(1)
            vector.add(DERNull.INSTANCE)
            val invalidSet = DERSet(vector)

            val exception = shouldThrow<InvalidChainException> {
                DnssecChain.decode(ORG_NAME, invalidSet)
            }

            exception.message shouldBe
                "Chain SET contains non-OCTET STRING item (${DERNull::class.simpleName})"
        }

        @Test
        fun `Chain should be initialised from valid SET`() {
            val response1 = Message()
            val response2 = Message(response1.header.id + 1)
            val chain = DnssecChain(ORG_NAME, listOf(response1, response2))
            val encoding = parseDer(chain.serialise()) as ASN1Set

            val chainDecoded = DnssecChain.decode(ORG_NAME, encoding)

            val responsesSerialised = chainDecoded.responses.map { it.toWire().asList() }
            responsesSerialised shouldContainExactlyInAnyOrder listOf(
                response1.toWire().asList(),
                response2.toWire().asList(),
            )
        }

        @Test
        fun `Org name should be stored`() {
            val response1 = Message()
            val chain = DnssecChain(ORG_NAME, listOf(response1))
            val encoding = parseDer(chain.serialise()) as ASN1Set

            val chainDecoded = DnssecChain.decode(ORG_NAME, encoding)

            chainDecoded.orgName shouldBe ORG_NAME
        }
    }

    @Nested
    @Isolated("We alter the resolver initialisers")
    inner class Verify {
        private val orgKeySpec = ORG_KEY_SPEC
        private val serviceOid = SERVICE_OID

        private val now = ZonedDateTime.now()
        private val datePeriod = now..now.plusSeconds(10)

        private val originalValidatingInitialiser = BaseDnssecChain.offlineResolverInitialiser

        @BeforeEach
        fun spyOnValidatingInitialiser() {
            val resolverSpy = makeMockValidatingResolver()
            BaseDnssecChain.offlineResolverInitialiser = { _, _ -> resolverSpy }
        }

        @AfterAll
        fun restoreValidatingInitialiser() {
            BaseDnssecChain.offlineResolverInitialiser = originalValidatingInitialiser
        }

        @Nested
        inner class VeraTxtResponse {
            @Test
            fun `VeraId response should use the _vera subdomain`() = runTest {
                val record = RECORD.copy(name = RECORD.name.makeSubdomain("sub"))
                val response = record.makeResponse()
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "Chain is missing VeraId TXT response"
            }

            @Test
            fun `VeraId response should use the TXT record type`() = runTest {
                val record = Record.newRecord(
                    RECORD.name,
                    Type.A,
                    RECORD.dClass,
                    RECORD.ttl,
                    byteArrayOf(1, 1, 1, 1),
                )
                val response = record.makeResponse()
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "Chain is missing VeraId TXT response"
            }

            @Test
            fun `VeraId response should use the IN class`() = runTest {
                val record = RECORD.copy(dClass = RECORD.dClass + 1)
                val response = record.makeResponse()
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "Chain is missing VeraId TXT response"
            }

            @Test
            fun `Multiple VeraId TXT responses should be refused`() = runTest {
                val responses = listOf(RECORD.makeResponse(), RECORD.makeResponse())
                val chain = DnssecChain(ORG_NAME, responses)

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "Chain contains multiple VeraId TXT responses"
            }

            @Test
            fun `VeraId TXT response should contain an answer`() = runTest {
                val response = RECORD.makeResponse()
                response.removeAllRecords(Section.ANSWER)
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "VeraId TXT response does not contain an answer"
            }

            @Test
            fun `Rdata should not be empty`() = runTest {
                val record = RECORD.copy(rdata = byteArrayOf())
                val response = record.makeResponseWithRrsig(datePeriod)
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "VeraId TXT answer rdata must contain one string (got 0)"
            }

            @Test
            fun `Answer should not have more than one rdata string`() = runTest {
                val record = RECORD.copy(
                    rdata = "one".toByteArray().txtRdataSerialise() + "two".toByteArray()
                        .txtRdataSerialise(),
                )
                val response = record.makeResponseWithRrsig(datePeriod)
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "VeraId TXT answer rdata must contain one string (got 2)"
            }

            @Test
            fun `Rdata should be valid`() = runTest {
                val record = RECORD.copy(rdata = "malformed".toByteArray().txtRdataSerialise())
                val response = record.makeResponseWithRrsig(datePeriod)
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "VeraId TXT response contains invalid RDATA"
                exception.cause should beInstanceOf<InvalidRdataException>()
            }
        }

        @Nested
        inner class KeySpec {
            @Test
            fun `Algorithm id should match that of specified key spec`() = runTest {
                val otherAlgorithm = KeyAlgorithm.RSA_3072
                otherAlgorithm shouldNotBe ORG_KEY_SPEC.algorithm
                val otherKeySpec = ORG_KEY_SPEC.copy(algorithm = otherAlgorithm)
                val otherFields = VERA_RDATA_FIELDS.copy(orgKeySpec = otherKeySpec)
                val record = RECORD.copyWithDifferentRdata(otherFields)
                val response = record.makeResponseWithRrsig(datePeriod)
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe
                    "Could not find VeraId record for specified key or service"
            }

            @Test
            fun `Key id should match that of specified key spec`() = runTest {
                val otherKeyId = "not-${ORG_KEY_SPEC.id}"
                val otherKeySpec = ORG_KEY_SPEC.copy(id = otherKeyId)
                val otherFields = VERA_RDATA_FIELDS.copy(orgKeySpec = otherKeySpec)
                val record = RECORD.copyWithDifferentRdata(otherFields)
                val response = record.makeResponseWithRrsig(datePeriod)
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe
                    "Could not find VeraId record for specified key or service"
            }
        }

        @Nested
        inner class ServiceOid {
            @Test
            fun `Absence of service OID should allow any service`() = runTest {
                val otherFields = VERA_RDATA_FIELDS.copy(service = null)
                val response =
                    RECORD.copyWithDifferentRdata(otherFields).makeResponseWithRrsig(datePeriod)
                val chain = DnssecChain(ORG_NAME, listOf(response))

                chain.verify(orgKeySpec, serviceOid, datePeriod)
            }

            @Test
            fun `Presence of service OID should only allow matching service`() = runTest {
                val otherFields = VERA_RDATA_FIELDS.copy(service = serviceOid)
                val response =
                    RECORD.copyWithDifferentRdata(otherFields).makeResponseWithRrsig(datePeriod)
                val chain = DnssecChain(ORG_NAME, listOf(response))

                chain.verify(orgKeySpec, serviceOid, datePeriod)
            }

            @Test
            fun `Presence of service OID should only deny mismatching service`() = runTest {
                val otherService = serviceOid.branch("42")
                val otherFields = VERA_RDATA_FIELDS.copy(service = otherService)
                val response =
                    RECORD.copyWithDifferentRdata(otherFields).makeResponseWithRrsig(datePeriod)
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe
                    "Could not find VeraId record for specified key or service"
            }
        }

        @Nested
        inner class DatePeriod {
            @Test
            fun `At least one response should have an RRSig`() = runTest {
                val response = RECORD.makeResponse()
                val chain = DnssecChain(ORG_NAME, listOf(response))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe "Chain does not contain RRSig records"
            }

            @Test
            fun `All RRSigs should have overlapping validity periods`() = runTest {
                val response1 = RECORD.makeResponseWithRrsig(datePeriod)
                val nonOverlappingPeriod =
                    datePeriod.endInclusive.plusSeconds(1)..datePeriod.endInclusive.plusSeconds(2)
                val response2 = RECORD.copy(name = RECORD.name.makeSubdomain("sub"))
                    .makeResponseWithRrsig(nonOverlappingPeriod)
                val chain =
                    DnssecChain(ORG_NAME, listOf(response1, response2))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe
                    "Chain contains RRSigs whose validity periods do not overlap"
            }

            @Test
            fun `Responses without RRSigs should be ignored if irrelevant`() = runTest {
                val responseWithRrsig = RECORD.makeResponseWithRrsig(datePeriod)
                val responseWithoutRrsig =
                    RECORD.copy(name = RECORD.name.makeSubdomain("sub")).makeResponse()
                val chain = DnssecChain(
                    ORG_NAME,
                    listOf(responseWithRrsig, responseWithoutRrsig),
                )

                chain.verify(orgKeySpec, serviceOid, datePeriod)
            }

            @Test
            fun `TTL override should truncate validity period of chain`() = runTest {
                val ttl = 3.seconds
                val record =
                    RECORD.copyWithDifferentRdata(VERA_RDATA_FIELDS.copy(ttlOverride = ttl))
                val response = record.makeResponseWithRrsig(datePeriod)
                val chainSpy = spy(DnssecChain(ORG_NAME, listOf(response)))

                chainSpy.verify(orgKeySpec, serviceOid, datePeriod)

                val expectedInstant =
                    datePeriod.endInclusive.toInstant().minus(ttl.toJavaDuration())
                verify(chainSpy).verify(expectedInstant)
            }

            @Test
            fun `TTL override should not truncate period if period is shorter`() = runTest {
                val ttl = 3.seconds
                val start = datePeriod.endInclusive.minus(ttl.toJavaDuration()).plusSeconds(1)
                val record =
                    RECORD.copyWithDifferentRdata(VERA_RDATA_FIELDS.copy(ttlOverride = ttl))
                val response = record.makeResponseWithRrsig(datePeriod)
                val chainSpy = spy(DnssecChain(ORG_NAME, listOf(response)))

                chainSpy.verify(orgKeySpec, serviceOid, start..datePeriod.endInclusive)

                verify(chainSpy).verify(start.toInstant())
            }

            @Test
            fun `TTL override from rdata with concrete service should take precedence`() = runTest {
                val concreteTtl = 3.seconds
                val concreteRecord = RECORD.copyWithDifferentRdata(
                    VERA_RDATA_FIELDS.copy(ttlOverride = concreteTtl, service = serviceOid),
                )
                val wildcardRecord = RECORD.copyWithDifferentRdata(
                    VERA_RDATA_FIELDS.copy(
                        ttlOverride = concreteTtl.plus(2.seconds),
                        service = null,
                    ),
                )
                val response = wildcardRecord.makeResponseWithRrsig(datePeriod)
                // Leave the concrete record to the end, to ensure we don't just pick the first
                response.addRecord(concreteRecord, Section.ANSWER)
                val chainSpy = spy(DnssecChain(ORG_NAME, listOf(response)))

                chainSpy.verify(orgKeySpec, serviceOid, datePeriod)

                val expectedInstant =
                    datePeriod.endInclusive.toInstant().minus(concreteTtl.toJavaDuration())
                verify(chainSpy).verify(expectedInstant)
            }

            @Test
            fun `Chain validity period should overlap with required period`() = runTest {
                val nonOverlappingPeriod =
                    datePeriod.endInclusive.plusSeconds(1)..datePeriod.endInclusive.plusSeconds(2)
                val responseWithRrsig = RECORD.makeResponseWithRrsig(nonOverlappingPeriod)
                val chain = DnssecChain(ORG_NAME, listOf(responseWithRrsig))

                val exception = shouldThrow<InvalidChainException> {
                    chain.verify(orgKeySpec, serviceOid, datePeriod)
                }

                exception.message shouldBe
                    "Chain validity period does not overlap with required period"
            }

            @Test
            fun `Verification time should be intersection of chain and specified one`() = runTest {
                val narrowPeriod =
                    datePeriod.endInclusive.minusSeconds(2)..datePeriod.endInclusive
                val response1WithRrsig = RECORD.makeResponseWithRrsig(narrowPeriod)
                val response2WithRrsig = RECORD.copy(name = RECORD.name.makeSubdomain("sub"))
                    .makeResponseWithRrsig(datePeriod)
                val chainSpy = spy(
                    DnssecChain(
                        ORG_NAME,
                        listOf(response1WithRrsig, response2WithRrsig),
                    ),
                )

                chainSpy.verify(orgKeySpec, serviceOid, datePeriod)

                verify(chainSpy).verify(narrowPeriod.start.toInstant())
            }
        }

        @Test
        fun `Multiple records for the same key and service should be refused`() = runTest {
            val fields = VERA_RDATA_FIELDS.copy(service = serviceOid)
            val record1 = RECORD.copyWithDifferentRdata(fields)
            val response = record1.makeResponseWithRrsig(datePeriod)
            val record2 = record1.copyWithDifferentRdata(
                fields.copy(ttlOverride = fields.ttlOverride.minus(1.seconds)),
            )
            response.addRecord(record2, Section.ANSWER)
            val chain = DnssecChain(ORG_NAME, listOf(response))

            val exception = shouldThrow<InvalidChainException> {
                chain.verify(orgKeySpec, serviceOid, datePeriod)
            }

            exception.message shouldBe "Found multiple VeraId records for the same key and service"
        }

        @Test
        fun `Multiple records for the same key and no service should be refused`() = runTest {
            val fields = VERA_RDATA_FIELDS.copy(service = null)
            val record1 = RECORD.copyWithDifferentRdata(fields)
            val response = record1.makeResponseWithRrsig(datePeriod)
            val record2 = record1.copyWithDifferentRdata(
                fields.copy(ttlOverride = fields.ttlOverride.minus(1.seconds)),
            )
            response.addRecord(record2, Section.ANSWER)
            val chain = DnssecChain(ORG_NAME, listOf(response))

            val exception = shouldThrow<InvalidChainException> {
                chain.verify(orgKeySpec, serviceOid, datePeriod)
            }

            exception.message shouldBe
                "Found multiple VeraId records for the same key and no service"
        }

        @Test
        fun `Valid chain should verify successfully`() = runTest {
            val response = RECORD.makeResponseWithRrsig(datePeriod)
            val chain = DnssecChain(ORG_NAME, listOf(response))

            chain.verify(orgKeySpec, serviceOid, datePeriod)
        }
    }
}
