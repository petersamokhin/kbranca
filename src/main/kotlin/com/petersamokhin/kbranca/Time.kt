package com.petersamokhin.kbranca

object Time {

    @JvmStatic
    fun unixTimeNow() = (System.currentTimeMillis() / 1000).toInt()

    @JvmStatic
    private fun bigEndian(unixTime: Int) =
        byteArrayOf((unixTime shr 24).toByte(), (unixTime shr 16).toByte(), (unixTime shr 8).toByte(), unixTime.toByte())

    @JvmStatic
    fun makeTimestamp() = bigEndian(unixTimeNow())
}
