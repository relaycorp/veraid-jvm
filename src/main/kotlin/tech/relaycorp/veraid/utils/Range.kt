@file:JvmName("Range")

package tech.relaycorp.veraid.utils

internal fun <T : Comparable<T>> ClosedRange<T>.intersect(otherRange: ClosedRange<T>):
    ClosedRange<T>? {
    val start = maxOf(this.start, otherRange.start)
    val end = minOf(this.endInclusive, otherRange.endInclusive)
    val range = start..end
    return if (range.isEmpty()) null else range
}
