package com.petersamokhin.kbranca

import org.bouncycastle.crypto.engines.ChaChaEngine

/**
 * We want to use a 24 byte nonce because that's what the Branca standard calls for.
 */
class XChaCha20Engine : ChaChaEngine(20) {

    override fun getAlgorithmName() = "XChaCha20"

    override fun getNonceSize() = NONCE_SIZE_BYTES

    companion object {
        private const val NONCE_SIZE_BYTES = 24
    }
}