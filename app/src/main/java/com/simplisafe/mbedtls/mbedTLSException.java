package com.simplisafe.mbedtls;

import org.jetbrains.annotations.Nullable;

public class mbedTLSException extends Exception {
    private final ErrorMessage errorMessage;
    private final Integer errorCode;

    public mbedTLSException(ErrorMessage errorMessage, @Nullable Integer errorCode) {
        super(errorMessage.getMessage());
        this.errorMessage = errorMessage;
        this.errorCode = errorCode;
    }

    public ErrorMessage getErrorMessage() {
        return errorMessage;
    }

    public Integer getErrorCode() {
        return errorCode;
    }

    public enum ErrorMessage {
        ENTROPY("Entropy setup failed. (mbedtls_ctr_drbg_seed)"),
        SSL_CONFIGURATION("Loading SSL configuration values failed. (mbedtls_ssl_config_defaults)"),
        SSL_SETUP("Setting up SSL Context failed. (mbedtls_ssl_setup)"),
        HANDSHAKE_STEP("Failed to execute handshake step. (mbedtls_ssl_handshake_client_step)"),
        PARSE_CERTIFICATE("Parsing certificates failed. (mbedtls_x509_crt_parse)"),
        PARSE_KEY_PAIR("Parsing key pair failed. (mbedtls_pk_parse_key)"),
        CONFIG_CLIENT_CERTIFICATE("Configuring client certificate failed. (mbedtls_ssl_conf_own_cert)"),
        WRITE("Write failed. (mbedtls_ssl_write)"),
        READ("Read failed. (mbedtls_ssl_read)");

        private final String message;

        ErrorMessage(String message) {
            this.message = message;
        }

        String getMessage() { return message; }
    }
}
