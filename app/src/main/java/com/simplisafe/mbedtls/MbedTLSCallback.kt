package com.simplisafe.mbedtls

interface MbedTLSCallback {
    fun logDebug(fileName: String, line: Int, log: String)
    fun read(data: ByteArray, dataLength: Int): Int
    fun write(data: ByteArray, dataLength: Int): Int
}
