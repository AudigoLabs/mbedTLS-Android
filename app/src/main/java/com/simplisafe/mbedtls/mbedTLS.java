package com.simplisafe.mbedtls;

public class mbedTLS {

    static {
        System.loadLibrary("libmbedtls");
    }

    public mbedTLS() { }

    public native int setupSSLContext();
}
