package com.petersamokhin.kbranca

import io.seruco.encoding.base62.Base62

import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.util.Arrays

object Bytes {
    @JvmStatic
    fun makeRandomNonce(): ByteArray {
        val bytes = ByteArray(24)
        try {
            SecureRandom.getInstanceStrong().nextBytes(bytes)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException(e)
        }

        return bytes
    }

    @JvmStatic
    fun addAll(one: ByteArray, two: ByteArray): ByteArray {
        val ret = one.copyOf(one.size + two.size)
        System.arraycopy(two, 0, ret, one.size, two.size)
        return ret
    }

    @JvmStatic
    fun base62Encode(input: ByteArray) = Base62.createInstance().encode(input)
}
