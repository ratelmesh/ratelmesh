package com.ratelmesh.android.service

import android.content.Context
import android.net.ConnectivityManager
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom

/**
 * Learns the public mapping for the fixed UDP port that GoBackend will open.
 *
 * Discovery happens immediately before WireGuard starts. Reusing the same local
 * port lets common cone/restricted NATs retain the mapping, while WireGuard's
 * persistent keepalives perform the actual bidirectional hole punch.
 */
internal object StunEndpointDiscovery {
    private const val MAGIC_COOKIE = 0x2112A442
    private const val BINDING_REQUEST = 0x0001
    private const val BINDING_SUCCESS = 0x0101
    private const val XOR_MAPPED_ADDRESS = 0x0020
    private const val HEADER_SIZE = 20
    private const val DEFAULT_HOST = "stun.cloudflare.com"
    private const val DEFAULT_PORT = 3478
    private const val TIMEOUT_MS = 2_500

    fun discover(context: Context, localPort: Int = 51820): String? = runCatching {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
            ?: return null
        val network = connectivity.activeNetwork ?: return null
        val serverAddress = network.getAllByName(DEFAULT_HOST)
            .firstOrNull { it is Inet4Address }
            ?: return null
        val transaction = ByteArray(12).also(SecureRandom()::nextBytes)
        val request = bindingRequest(transaction)

        DatagramSocket(null).use { socket ->
            socket.reuseAddress = true
            socket.bind(InetSocketAddress(localPort))
            network.bindSocket(socket)
            socket.soTimeout = TIMEOUT_MS
            socket.send(
                DatagramPacket(
                    request,
                    request.size,
                    InetSocketAddress(serverAddress, DEFAULT_PORT),
                ),
            )
            val response = ByteArray(1280)
            val packet = DatagramPacket(response, response.size)
            socket.receive(packet)
            parseBindingResponse(response.copyOf(packet.length), transaction)
        }
    }.getOrNull()

    internal fun bindingRequest(transaction: ByteArray): ByteArray {
        require(transaction.size == 12)
        return ByteArray(HEADER_SIZE).also { packet ->
            putU16(packet, 0, BINDING_REQUEST)
            putU16(packet, 2, 0)
            putU32(packet, 4, MAGIC_COOKIE)
            transaction.copyInto(packet, 8)
        }
    }

    internal fun parseBindingResponse(packet: ByteArray, transaction: ByteArray): String? {
        if (packet.size < HEADER_SIZE || transaction.size != 12) return null
        if (u16(packet, 0) != BINDING_SUCCESS || u32(packet, 4) != MAGIC_COOKIE) return null
        if (!packet.copyOfRange(8, 20).contentEquals(transaction)) return null
        val messageLength = u16(packet, 2)
        if (HEADER_SIZE + messageLength > packet.size) return null

        var offset = HEADER_SIZE
        val end = HEADER_SIZE + messageLength
        while (offset + 4 <= end) {
            val type = u16(packet, offset)
            val length = u16(packet, offset + 2)
            val value = offset + 4
            if (value + length > end) return null
            if (type == XOR_MAPPED_ADDRESS && length >= 8) {
                val family = packet[value + 1].toInt() and 0xff
                val port = u16(packet, value + 2) xor (MAGIC_COOKIE ushr 16)
                if (port == 0) return null
                if (family == 0x01) {
                    val cookie = byteArrayOf(0x21, 0x12, 0xA4.toByte(), 0x42)
                    val addressBytes = ByteArray(4) { index ->
                        (packet[value + 4 + index].toInt() xor cookie[index].toInt()).toByte()
                    }
                    val address = InetAddress.getByAddress(addressBytes).hostAddress ?: return null
                    return "$address:$port"
                }
            }
            offset = value + length + ((4 - length % 4) % 4)
        }
        return null
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun u32(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 24) or
            ((bytes[offset + 1].toInt() and 0xff) shl 16) or
            ((bytes[offset + 2].toInt() and 0xff) shl 8) or
            (bytes[offset + 3].toInt() and 0xff)

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
