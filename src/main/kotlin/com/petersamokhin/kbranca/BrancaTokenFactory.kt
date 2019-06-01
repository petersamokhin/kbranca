package com.petersamokhin.kbranca

import io.seruco.encoding.base62.Base62
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.nio.ByteBuffer
import java.util.Arrays

/**
 * Constructs Branca tokens from provided payloads as well as validates and unpacks them.
 */
class BrancaTokenFactory(secretKey: ByteArray) {
    private val key: ByteArray

    init {
        if (secretKey.size != 32) {
            throw IllegalArgumentException("Secret key must be 32 bytes")
        }
        this.key = secretKey.copyOf(secretKey.size)
    }

    /**
     * Generates a Branca token with plain text as the payload using the provided nonce. Make sure this nonce is plenty random.
     *
     * @param source Source bytes
     * @param nonce Nonce
     * @return Encoded byte array
     */
    @JvmOverloads
    fun encode(source: ByteArray, nonce: ByteArray = Bytes.makeRandomNonce()): ByteArray {

        val header = ByteBuffer.allocate(1 + 4 + 24)

        /* Version (1B) */
        header.put(0, VERSION)
        header.position(1)

        /* Timestamp (4B) */
        val timestamp = Time.makeTimestamp()
        header.put(timestamp, 0, timestamp.size)
        header.position(5)

        /* Nonce (24B) */
        header.put(nonce, 0, nonce.size)
        header.position(29)

        /* Ciphertext (*B) */
        val cipherAndTag = encrypt(header.array(), source, nonce)
        val headerAndCipher = Bytes.addAll(header.array(), cipherAndTag)

        return Bytes.base62Encode(headerAndCipher)
    }

    private fun encrypt(header: ByteArray, plaintext: ByteArray, nonce: ByteArray): ByteArray {
        val cp = KeyParameter(key)
        val params = ParametersWithIV(cp, nonce)
        val engine = XChaCha20Engine()
        engine.init(true, params)
        val encrypted = ByteArray(plaintext.size + TAG_LENGTH)
        engine.processBytes(plaintext, 0, plaintext.size, encrypted, 0)

        /* Generate Poly13509 and append to cipher */
        with(Poly1305()) {
            init(cp)
            update(header, 0, header.size)
            doFinal(encrypted, plaintext.size)
        }
        return encrypted
    }

    private fun decrypt(header: ByteArray, plaintext: ByteArray, nonce: ByteArray, mac: ByteArray): ByteArray {
        val cp = KeyParameter(key)
        val params = ParametersWithIV(cp, nonce)

        val headerMac = ByteArray(16)

        with(Poly1305()) {
            init(cp)
            update(header, 0, header.size)
            doFinal(headerMac, 0)
        }

        if (!Arrays.equals(headerMac, mac)) {
            throw IllegalArgumentException("Auth failed")
        }

        val engine = XChaCha20Engine()
        engine.init(false, params)
        val decrypted = ByteArray(plaintext.size)
        engine.processBytes(plaintext, 0, plaintext.size, decrypted, 0)
        return decrypted
    }

    /**
     * Given a Branca token in the correct format this method returns the plaintext
     *
     * @param token valid Branca token
     * @return decoded byte array
     */
    fun decode(token: ByteArray): ByteArray {
        val decoded = Base62.createInstance().decode(token)

        if (decoded[0] != VERSION) {
            throw IllegalArgumentException("Not a valid version")
        }

        val cypherText = Arrays.copyOfRange(decoded, HEADER_LENGTH, decoded.size)
        val nonce = Arrays.copyOfRange(decoded, 5, decoded.size - cypherText.size)
        val tag = Arrays.copyOfRange(decoded, decoded.size - TAG_LENGTH, decoded.size)
        val header = Arrays.copyOfRange(decoded, 0, HEADER_LENGTH)
        val decrypted = decrypt(header, cypherText, nonce, tag)
        return Arrays.copyOfRange(decrypted, 0, decrypted.size - 16)
    }

    companion object {
        private const val VERSION = 0xBA.toByte() // magic branca byte
        private const val TAG_LENGTH = 16
        private const val HEADER_LENGTH = 29
    }
}