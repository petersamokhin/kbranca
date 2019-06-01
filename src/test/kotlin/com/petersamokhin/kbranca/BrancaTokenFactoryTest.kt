package com.petersamokhin.kbranca

import org.junit.Test

import org.junit.Assert.*
import java.util.Random

class BrancaTokenFactoryTest {

    @Test
    fun encode() {
        for (i in 0..4) {
            val key = ByteArray(32)
            Random().nextBytes(key)
            val factory = BrancaTokenFactory(key)
            val plaintext = "{\"key_$i\": \"value_$i\"}"
            val encoded = factory.encode(plaintext.toByteArray())
            val decoded = factory.decode(encoded)
            assertEquals(plaintext, String(decoded))
        }
    }
}