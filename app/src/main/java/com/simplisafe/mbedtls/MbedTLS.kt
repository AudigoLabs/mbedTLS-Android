package com.simplisafe.mbedtls

import com.simplisafe.mbedtls.MbedTLSException.ErrorMessage

@Suppress("UNUSED")
class MbedTLS {
    interface MbedTLSCallback {
        fun writeCallback(data: ByteArray, dataLength: Int): Int
        fun readCallback(dataLength: Int): ByteArray?
        fun handshakeCompleted()
        fun logDebug(fileName: String, line: Int, log: String)
    }

    private var callbackMethods: MbedTLSCallback? = null

    private var currentHandshakeStep: HandshakeSteps = HandshakeSteps.HELLO_REQUEST

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

    init {
        if (init() != 0) {
            throw MbedTLSException(ErrorMessage.ENTROPY, null)
        }
        getClassObject(this)
    }

    private external fun init(): Int
    private external fun getClassObject(mbedtls: MbedTLS?)
    private external fun setIOFuncs(contextParameter: String?)
    private external fun setMinimumProtocolVersion(version: Int)
    private external fun setMaximumProtocolVersion(version: Int)
    private external fun executeHandshakeStep(): Int
    private val currentHandshakeState: Int
        external get

    private external fun enableDebug(level: Int)
    private external fun setupSSLContextNative(): Int
    private external fun configureClientCertNative(certificateBytes: ByteArray?, keyPair: ByteArray?): Int
    private external fun configureRootCACertNative(certificateBytes: ByteArray?): Int
    private external fun getIssuerNameNative(certificateBytes: ByteArray?): ByteArray?

    external fun configureCipherSuites(cipherSuites: IntArray?)
    external fun write(data: ByteArray?): Boolean
    external fun read(length: Int, buffer: ByteArray?): Boolean

    fun setIOFunctions(contextParameter: String?, callback: MbedTLSCallback) {
        setIOFuncs(contextParameter)
        callbackMethods = callback
    }

    fun setTLSVersion(minimum: ProtocolVersion, maximum: ProtocolVersion) {
        setMinimumProtocolVersion(minimum.value)
        setMaximumProtocolVersion(maximum.value)
    }

    private fun writeCallback(data: ByteArray, dataLength: Int): Int {
        return callbackMethods?.writeCallback(data, dataLength) ?: 0
    }

    private fun readCallback(dataLength: Int): ByteArray? {
        return callbackMethods?.readCallback(dataLength)
    }

    @Throws(MbedTLSException::class)
    fun setupSSLContext() {
        when (setupSSLContextNative()) {
            552 -> throw MbedTLSException(ErrorMessage.SSL_CONFIGURATION, null)
            553 -> throw MbedTLSException(ErrorMessage.SSL_SETUP, null)
        }
    }

    @Throws(MbedTLSException::class)
    fun configureClientCert(certificateBytes: ByteArray?, keyPair: ByteArray?) {
        when (configureClientCertNative(certificateBytes, keyPair)) {
            555 -> {
                throw MbedTLSException(ErrorMessage.PARSE_CERTIFICATE, null)
            }

            556 -> {
                throw MbedTLSException(ErrorMessage.PARSE_KEY_PAIR, null)
            }

            557 -> {
                throw MbedTLSException(ErrorMessage.CONFIG_CLIENT_CERTIFICATE, null)
            }
        }
    }

    @Throws(MbedTLSException::class)
    fun configureRootCACert(certificateBytes: ByteArray?) {
        if (configureRootCACertNative(certificateBytes) != 0) {
            throw MbedTLSException(ErrorMessage.PARSE_CERTIFICATE, null)
        }
    }

    @Throws(MbedTLSException::class)
    fun getIssuerName(certificateBytes: ByteArray?): ByteArray {
        return getIssuerNameNative(certificateBytes) ?: throw MbedTLSException(ErrorMessage.PARSE_CERTIFICATE, null)
    }

    @Throws(MbedTLSException::class)
    private fun handshakeStep(): Boolean {
        val ret = executeHandshakeStep()
        if (ret != 0) {
            throw MbedTLSException(ErrorMessage.HANDSHAKE_STEP, ret)
        }
        // Check if the ssl_context state is equal to the next enum state that we are expecting.
        return if (this.currentHandshakeState == currentHandshakeStep.next().value) {
            currentHandshakeStep = currentHandshakeStep.next()
            true
        } else {
            throw MbedTLSException(ErrorMessage.HANDSHAKE_STEP, ret)
        }
    }

    @Throws(MbedTLSException::class)
    fun executeNextHandshakeStep() {
        when (currentHandshakeStep) {
            HandshakeSteps.HELLO_REQUEST -> {
                handshakeStep()
                handshakeStep()
            }

            HandshakeSteps.HANDSHAKE_COMPLETED -> {
                callbackMethods?.handshakeCompleted()
            }

            else -> {
                if (handshakeStep()) {
                    when (currentHandshakeStep) {
                        HandshakeSteps.CLIENT_CERTIFICATE,
                        HandshakeSteps.FLUSH_BUFFERS,
                        HandshakeSteps.HANDSHAKE_WRAPUP,
                        HandshakeSteps.HANDSHAKE_COMPLETED,
                            -> executeNextHandshakeStep()

                        else -> {}
                    }
                }
            }
        }
    }

    fun enableDebugMessages(level: DebugThresholdLevel) {
        enableDebug(level.value)
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
