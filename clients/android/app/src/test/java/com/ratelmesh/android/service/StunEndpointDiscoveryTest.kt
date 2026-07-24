package com.ratelmesh.android.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class StunEndpointDiscoveryTest {
    @Test
    fun parsesIpv4XorMappedAddress() {
        val transaction = ByteArray(12) { it.toByte() }
        val response = ByteArray(32)
        putU16(response, 0, 0x0101)
        putU16(response, 2, 12)
        putU32(response, 4, 0x2112A442)
        transaction.copyInto(response, 8)
        putU16(response, 20, 0x0020)
        putU16(response, 22, 8)
        response[25] = 0x01
        putU16(response, 26, 41123 xor 0x2112)
        val address = byteArrayOf(203.toByte(), 0, 113, 9)
        val cookie = byteArrayOf(0x21, 0x12, 0xA4.toByte(), 0x42)
        for (index in address.indices) {
            response[28 + index] = (address[index].toInt() xor cookie[index].toInt()).toByte()
        }

        assertEquals(
            "203.0.113.9:41123",
            StunEndpointDiscovery.parseBindingResponse(response, transaction),
        )
    }

    @Test
    fun rejectsMismatchedTransaction() {
        val transaction = ByteArray(12)
        val response = StunEndpointDiscovery.bindingRequest(transaction).also {
            putU16(it, 0, 0x0101)
            it[8] = 1
        }
        assertNull(StunEndpointDiscovery.parseBindingResponse(response, transaction))
    }

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun putU32(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 24).toByte()
        bytes[offset + 1] = (value ushr 16).toByte()
        bytes[offset + 2] = (value ushr 8).toByte()
        bytes[offset + 3] = value.toByte()
    }
}
