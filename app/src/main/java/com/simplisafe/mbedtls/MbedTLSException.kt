package com.simplisafe.mbedtls

import java.io.IOException

class MbedTLSException(errorMessage: ErrorMessage, errorCode: Int?) : IOException(
    "${errorMessage.message} (Error code: $errorCode)",
) {
    enum class ErrorMessage(val message: String) {
        ENTROPY("Entropy setup failed. (mbedtls_ctr_drbg_seed)"),
        SSL_CONFIGURATION("Loading SSL configuration values failed. (mbedtls_ssl_config_defaults)"),
        SSL_SETUP("Setting up SSL Context failed. (mbedtls_ssl_setup)"),
        HANDSHAKE_STEP("Failed to execute handshake step. (mbedtls_ssl_handshake_client_step)"),
        PARSE_CERTIFICATE("Parsing certificates failed. (mbedtls_x509_crt_parse)"),
        PARSE_KEY_PAIR("Parsing key pair failed. (mbedtls_pk_parse_key)"),
        CONFIG_CLIENT_CERTIFICATE("Configuring client certificate failed. (mbedtls_ssl_conf_own_cert)"),
        WRITE("Write failed. (mbedtls_ssl_write)"),
        READ("Read failed. (mbedtls_ssl_read)");
    }
}
