import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class PlaceholderTest {
    @Test
    fun placeholder() = runBlocking {
        assertEquals(2, 2)
    }
}
