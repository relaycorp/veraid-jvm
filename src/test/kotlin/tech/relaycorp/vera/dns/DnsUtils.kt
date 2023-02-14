package tech.relaycorp.vera.dns

import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.whenever
import java.util.concurrent.CompletableFuture
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.dnssec.ValidatingResolver

fun makeMockValidatingResolver(response: Message? = null): ValidatingResolver {
    val finalResponse = response ?: makeSuccessfulEmptyResponse()
    val mockResolver = mock<ValidatingResolver>()
    whenever(mockResolver.sendAsync(any())).thenReturn(
        CompletableFuture.completedFuture(finalResponse)
    )
    return mockResolver
}

fun makeSuccessfulEmptyResponse(): Message {
    val response = Message()
    response.header.setFlag(Flags.AD.toInt())
    return response
}
