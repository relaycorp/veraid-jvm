package tech.relaycorp.veraid

/**
 * VeraId Member.
 *
 * @property orgName The organisation name.
 * @property userName The user's name if the member is a user, or `null` if it's a bot.
 */
public data class Member(val orgName: String, val userName: String?)
