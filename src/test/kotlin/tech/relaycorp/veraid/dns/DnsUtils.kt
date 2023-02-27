package tech.relaycorp.veraid.dns

import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.whenever
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.dnssec.ValidatingResolver
import java.util.concurrent.CompletableFuture

fun makeMockValidatingResolver(response: Message? = null): ValidatingResolver {
    val finalResponse = response ?: makeSuccessfulEmptyResponse()
    val mockResolver = mock<ValidatingResolver>()
    whenever(mockResolver.sendAsync(any())).thenReturn(
        CompletableFuture.completedFuture(finalResponse),
    )
    return mockResolver
}

fun makeSuccessfulEmptyResponse(): Message {
    val response = Message()
    response.header.setFlag(Flags.AD.toInt())
    return response
}
