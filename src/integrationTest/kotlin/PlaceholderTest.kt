import io.kotest.matchers.shouldBe
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class PlaceholderTest {
    @Test
    fun placeholder() = runBlocking {
        2 shouldBe 2
    }
}
