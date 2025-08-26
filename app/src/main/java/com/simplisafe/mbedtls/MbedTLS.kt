package com.simplisafe.mbedtls

import timber.log.Timber

@Suppress("UNUSED")
class MbedTLS {

    private var callbackMethods: MbedTLSCallback? = null

    private var currentHandshakeStep: HandshakeSteps = HandshakeSteps.HELLO_REQUEST

    internal var pointer: Long = 0L

    enum class HandshakeSteps(val value: Int) {
        HELLO_REQUEST(0),
        CLIENT_HELLO(1),
        SERVER_HELLO(2),
        SERVER_CERTIFICATE(3),
        SERVER_KEY_EXCHANGE(4),
        SERVER_CERTIFICATE_REQUEST(5),
        SERVER_HELLO_DONE(6),
        CLIENT_CERTIFICATE(7),
        CLIENT_KEY_EXCHANGE(8),
        CERTIFICATE_VERIFY(9),
        CLIENT_CHANGE_CIPHER_SPEC(10),
        CLIENT_FINISHED(11),
        SERVER_CHANGE_CIPHER_SPEC(12),
        SERVER_FINISHED(13),
        FLUSH_BUFFERS(14),
        HANDSHAKE_WRAPUP(15),
        HANDSHAKE_COMPLETED(16);

        fun next(): HandshakeSteps {
            return entries[ordinal + 1]
        }
    }

    enum class ProtocolVersion(val value: Int) {
        SSLProtocol10(1),
        SSLProtocol11(2),
        SSLProtocol12(3)
    }

    enum class DebugThresholdLevel(val value: Int) {
        NO_DEBUG(0),
        ERROR(1),
        STATE_CHANGE(2),
        INFORMATIONAL(3),
        VERBOSE(4)
    }

    enum class Transport(val value: Int) {
        STREAM(0),
        DATAGRAM(1),
    }

    private external fun deallocateClient(handle: Long)
    private external fun initClientHandshake(handle: Long): Int
    private val currentHandshakeState: Int
        external get

    private external fun clientReadNative(handle: Long, data: ByteArray, dataLength: Int): Int
    private external fun clientWriteNative(handle: Long, data: ByteArray, dataLength: Int): Int

    private external fun initClientImpl(
        transport: Int,
        cipherSuites: IntArray,
        numCipherSuitesLength: Int,
        psk: ByteArray,
        pskLength: Int,
        pskId: ByteArray,
        pskIdLength: Int,
    ): Long

    fun clientRead(data: ByteArray, dataLength: Int): Int {
        return clientReadNative(pointer, data, dataLength)
    }

    fun clientWrite(data: ByteArray, dataLength: Int): Int {
        return clientWriteNative(pointer, data, dataLength)
    }

    fun configurePsk(pskId: String, pskSecret: ByteArray) {}

    fun deallocate() {
        deallocateClient(pointer)
        pointer = 0L
    }

    fun initClient(
        cipherSuites: IntArray,
        psk: ByteArray,
        pskId: String,
        transport: Transport,
    ): Boolean {
        pointer = initClientImpl(
            transport = transport.value,
            cipherSuites = cipherSuites,
            numCipherSuitesLength = cipherSuites.size,
            psk = psk,
            pskLength = psk.size,
            pskId = pskId.toByteArray(),
            pskIdLength = pskId.toCharArray().size,
        )

        return pointer != 0L
    }

    fun setIOFunctions(contextParameter: String?, callback: MbedTLSCallback) {
        callbackMethods = callback
    }

    private fun read(data: ByteArray, dataLength: Int): Int {
        return callbackMethods?.read(data, dataLength) ?: -0x6900
    }

    private fun write(data: ByteArray, dataLength: Int): Int {
        return callbackMethods?.write(data, dataLength) ?: -1
    }

    @Throws(MbedTLSException::class)
    fun initiateClientHandshake(): Int {
        return initClientHandshake(pointer)
    }

    private fun printDebugMessage(i: Int, iArray: CharArray, j: Int, jArray: CharArray) {
        Timber.d("$i: ${String(iArray)}, $j: ${String(jArray)}")
    }

    private fun debugUtility(fileName: ByteArray, lineNumber: Int, log: ByteArray) {
        callbackMethods?.logDebug(String(fileName), lineNumber, String(log))
    }

    companion object {
        init {
            System.loadLibrary("libmbedtls")
        }
    }
}
