package com.ratelmesh.android.service

import java.math.BigInteger
import java.net.InetAddress

/** CIDR subtraction used to keep directRoutes outside Android's VPN route table. */
internal object CidrRoutes {
    fun subtract(routes: List<String>, exclusions: List<String>): List<String> {
        val cuts = exclusions.map(Network::parse)
        return routes
            .map(Network::parse)
            .flatMap { route -> cuts.fold(listOf(route)) { remaining, cut -> remaining.flatMap { it.minus(cut) } } }
            .sortedWith(compareBy<Network>({ it.bits }, { it.address }, { it.prefix }))
            .map(Network::toString)
    }

    private data class Network(val address: BigInteger, val prefix: Int, val bits: Int) {
        init {
            require(prefix in 0..bits) { "Invalid CIDR prefix /$prefix" }
        }

        fun minus(cut: Network): List<Network> {
            if (bits != cut.bits || !overlaps(cut)) return listOf(this)
            if (cut.contains(this)) return emptyList()
            if (prefix == bits) return listOf(this)
            val childPrefix = prefix + 1
            val step = BigInteger.ONE.shiftLeft(bits - childPrefix)
            val left = Network(address, childPrefix, bits)
            val right = Network(address.add(step), childPrefix, bits)
            return left.minus(cut) + right.minus(cut)
        }

        private fun contains(other: Network): Boolean =
            bits == other.bits && prefix <= other.prefix && address == other.address.and(mask(bits, prefix))

        private fun overlaps(other: Network): Boolean = contains(other) || other.contains(this)

        override fun toString(): String {
            val raw = address.toByteArray()
            val bytes = ByteArray(bits / 8)
            val sourceOffset = (raw.size - bytes.size).coerceAtLeast(0)
            val targetOffset = (bytes.size - raw.size).coerceAtLeast(0)
            val count = minOf(raw.size, bytes.size)
            raw.copyInto(bytes, targetOffset, sourceOffset, sourceOffset + count)
            return "${InetAddress.getByAddress(bytes).hostAddress}/$prefix"
        }

        companion object {
            fun parse(value: String): Network {
                val pieces = value.trim().split('/')
                require(pieces.size == 2) { "Invalid CIDR: $value" }
                val literal = pieces[0]
                require(literal.contains(':') || literal.matches(Regex("[0-9.]+"))) { "Invalid IP: $literal" }
                val bytes = InetAddress.getByName(literal).address
                val bits = bytes.size * 8
                val prefix = pieces[1].toIntOrNull() ?: error("Invalid CIDR prefix: $value")
                require(prefix in 0..bits) { "Invalid CIDR prefix: $value" }
                val normalized = BigInteger(1, bytes).and(mask(bits, prefix))
                return Network(normalized, prefix, bits)
            }
        }
    }

    private fun mask(bits: Int, prefix: Int): BigInteger {
        if (prefix == 0) return BigInteger.ZERO
        val all = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE)
        return all.xor(BigInteger.ONE.shiftLeft(bits - prefix).subtract(BigInteger.ONE))
    }
}
