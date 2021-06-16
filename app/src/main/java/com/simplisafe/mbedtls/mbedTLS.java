package com.simplisafe.mbedtls;

import static com.simplisafe.mbedtls.mbedTLSException.ErrorMessage.CONFIG_CLIENT_CERTIFICATE;
import static com.simplisafe.mbedtls.mbedTLSException.ErrorMessage.ENTROPY;
import static com.simplisafe.mbedtls.mbedTLSException.ErrorMessage.PARSE_CERTIFICATE;
import static com.simplisafe.mbedtls.mbedTLSException.ErrorMessage.PARSE_KEY_PAIR;
import static com.simplisafe.mbedtls.mbedTLSException.ErrorMessage.SSL_CONFIGURATION;
import static com.simplisafe.mbedtls.mbedTLSException.ErrorMessage.SSL_SETUP;
import static com.simplisafe.mbedtls.mbedTLSException.ErrorMessage.HANDSHAKE_STEP;

public class mbedTLS {

    public interface mbedTLSCallback {
        int writeCallback(byte[] data, int datalength);
        byte[] readCallback(int datalength);
        void handshakeCompleted();
        void logDebug(String fileName, int line, String log);
    }

    private mbedTLSCallback callbackMethods;

    public HandshakeSteps currentHandshakeStep = HandshakeSteps.HELLO_REQUEST;

    public enum HandshakeSteps {
        HELLO_REQUEST(0), CLIENT_HELLO(1),
        SERVER_HELLO(2), SERVER_CERTIFICATE(3), SERVER_KEY_EXCHANGE(4), SERVER_CERTIFICATE_REQUEST(5), SERVER_HELLO_DONE(6),
        CLIENT_CERTIFICATE(7), CLIENT_KEY_EXCHANGE(8), CERTIFICATE_VERIFY(9), CLIENT_CHANGE_CIPHER_SPEC(10), CLIENT_FINISHED(11),
        SERVER_CHANGE_CIPHER_SPEC(12), SERVER_FINISHED(13), FLUSH_BUFFERS(14), HANDSHAKE_WRAPUP(15), HANDSHAKE_COMPLETED(16);

        private final int value;

        HandshakeSteps(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public HandshakeSteps next() {
            return values()[ordinal() + 1];
        }
    }

    public enum ProtocolVersion {
        SSLProtocol10 (1), SSLProtocol11(2), SSLProtocol12(3);

        private final int value;

        ProtocolVersion(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    public enum DebugThresholdLevel {
        NO_DEBUG (0), ERROR(1), STATE_CHANGE(2), INFORMATIONAL(3), VERBOSE(4);

        private final int value;

        DebugThresholdLevel(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    static {
        System.loadLibrary("libmbedtls");
    }

    public mbedTLS() throws mbedTLSException {
        if (init() != 0) {
            throw new mbedTLSException(ENTROPY, null);
        }
        getClassObject(this);
    }

    private native int init();
    private native void getClassObject(mbedTLS mbedtls);
    private native void setIOFuncs(String contextParameter);
    private native void setMinimumProtocolVersion(int version);
    private native void setMaximumProtocolVersion(int version);
    private native int executeHandshakeStep();
    private native int getCurrentHandshakeState();
    private native void enableDebug(int level);
    private native int setupSSLContextNative();
    private native int configureClientCertNative(byte[] certificateBytes, byte[] keyPair);
    private native int configureRootCACertNative(byte[] certificateBytes);
    private native byte[] getIssuerNameNative(byte[] certificateBytes);

    public native void configureCipherSuites(int[] ciphersuites);
    public native boolean write(byte[] data);
    public native boolean read(int length, byte[] buffer);

    public void setIOFunctions(String contextParameter, mbedTLSCallback callback) {
        setIOFuncs(contextParameter);
        callbackMethods = callback;
    }

    public void setTLSVersion(ProtocolVersion minimum, ProtocolVersion maximum) {
        setMinimumProtocolVersion(minimum.getValue());
        setMaximumProtocolVersion(maximum.getValue());
    }

    private int writeCallback(byte[] data, int dataLength) {
        return callbackMethods.writeCallback(data, dataLength);
    }

    private byte[] readCallback(int dataLength) {
        return callbackMethods.readCallback(dataLength);
    }

    public void setupSSLContext() throws mbedTLSException {
        int ret = setupSSLContextNative();
        if (ret == 552) {
            throw new mbedTLSException(SSL_CONFIGURATION, null);
        } else if (ret == 553) {
            throw new mbedTLSException(SSL_SETUP, null);
        }
    }

    public void configureClientCert(byte[] certificateBytes, byte[] keyPair) throws mbedTLSException {
        int ret = configureClientCertNative(certificateBytes, keyPair);
        if (ret == 555) {
            throw new mbedTLSException(PARSE_CERTIFICATE, null);
        } else if (ret == 556) {
            throw new mbedTLSException(PARSE_KEY_PAIR, null);
        } else if (ret == 557) {
            throw new mbedTLSException(CONFIG_CLIENT_CERTIFICATE, null);
        }
    }

    public void configureRootCACert(byte[] certificateBytes) throws mbedTLSException {
        if (configureRootCACertNative(certificateBytes) != 0) {
            throw new mbedTLSException(PARSE_CERTIFICATE, null);
        }
    }

    public byte[] getIssuerName(byte[] certificateBytes) throws mbedTLSException {
        byte[] issuerName = getIssuerNameNative(certificateBytes);
        if (issuerName == null) {
            throw new mbedTLSException(PARSE_CERTIFICATE, null);
        }
        return issuerName;
    }

    private boolean handshakeStep() throws mbedTLSException {
        int ret = executeHandshakeStep();
        if (ret != 0) {
            throw new mbedTLSException(HANDSHAKE_STEP, ret);
        }
        // Check if the ssl_context state is equal to the next enum state that we are expecting.
        if (getCurrentHandshakeState() == currentHandshakeStep.next().getValue()) {
            currentHandshakeStep = currentHandshakeStep.next();
            return true;
        } else {
            throw new mbedTLSException(HANDSHAKE_STEP, ret);
        }
    }

    public void executeNextHandshakeStep() throws mbedTLSException {
        if (currentHandshakeStep == HandshakeSteps.HELLO_REQUEST) {
            handshakeStep();
            handshakeStep();
        } else if (currentHandshakeStep == HandshakeSteps.HANDSHAKE_COMPLETED) {
            callbackMethods.handshakeCompleted();
        } else {
            if (handshakeStep()) {
                switch (currentHandshakeStep) {
                    case CLIENT_CERTIFICATE:
                    case FLUSH_BUFFERS:
                    case HANDSHAKE_WRAPUP:
                    case HANDSHAKE_COMPLETED:
                        executeNextHandshakeStep();
                        break;
                    default:
                        break;
                }
            }
        }
    }

    public void enableDebugMessages(DebugThresholdLevel level) {
        enableDebug(level.getValue());
    }

    private void debugUtility(byte[] fileName, int lineNumber, byte[] log) {
        callbackMethods.logDebug(new String(fileName), lineNumber, new String(log));
    }

}
