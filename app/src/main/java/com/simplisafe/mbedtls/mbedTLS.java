package com.simplisafe.mbedtls;

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
        SERVER_CHANGE_CIPHER_SPEC(12), SERVER_FINISHED(13), FLUSH_BUFFERS(14), HANDSHAKE_WRAPUP(15);

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

    public mbedTLS() {
        init();
        getClassObject(this);
    }

    private native void init();
    private native void getClassObject(mbedTLS mbedtls);
    private native void setIOFuncs(String contextParameter);
    private native void setMinimumProtocolVersion(int version);
    private native void setMaximumProtocolVersion(int version);
    private native int executeHandshakeStep();
    private native void enableDebug(int level);
    private native void fixPeerCert();

    public native void setupSSLContext();
    public native void configureCipherSuites(int[] ciphersuites);
    public native void configureClientCert(byte[] certificateBytes, byte[] keyPair);
    public native void configureRootCACert(byte[] certificateBytes);
    public native byte[] getIssuerName(byte[] certificateBytes);
    public native boolean write(byte[] data);

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

    public void executeNextHandshakeStep() {
        if (currentHandshakeStep == HandshakeSteps.HELLO_REQUEST) {
            executeHandshakeStep();
            executeHandshakeStep();
            currentHandshakeStep = HandshakeSteps.SERVER_HELLO;
        } else if (currentHandshakeStep == HandshakeSteps.HANDSHAKE_WRAPUP) {
            callbackMethods.handshakeCompleted();
        } else {
            if (executeHandshakeStep() == 0) {
                currentHandshakeStep = currentHandshakeStep.next();

                switch (currentHandshakeStep) {
                    case CLIENT_CERTIFICATE:
                    case FLUSH_BUFFERS:
                    case HANDSHAKE_WRAPUP:
                        executeNextHandshakeStep();
                        break;
                    case SERVER_KEY_EXCHANGE:
                        fixPeerCert();
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
