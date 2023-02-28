@file:JvmName("Periods")

package tech.relaycorp.veraid

import java.time.Instant
import java.time.ZonedDateTime

internal typealias InstantPeriod = ClosedRange<Instant>
public typealias DatePeriod = ClosedRange<ZonedDateTime>

internal fun DatePeriod.toInstantPeriod(): InstantPeriod =
    start.toInstant()..endInclusive.toInstant()
