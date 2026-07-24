package com.ratelmesh.android.service

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class TunnelConfigParserTest {
    @Test
    fun rendersMobileContractAndSubtractsDirectRoutes() {
        val json = """
            {
              "version": 7,
              "active": true,
              "privateKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              "listenPort": 51820,
              "addresses": ["100.64.0.2/32"],
              "dnsServers": ["100.100.100.100"],
              "peers": [{
                "publicKey": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "presharedKey": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
                "endpoint": "203.0.113.4:51820",
                "allowedIPs": ["0.0.0.0/0"],
                "persistentKeepalive": 25
              }],
              "directRoutes": ["10.0.0.0/8"],
              "blockRoutes": []
            }
        """.trimIndent()

        val result = TunnelConfigParser.toWgQuick(json, "com.ratelmesh.android")

        assertTrue(result.contains("ExcludedApplications = com.ratelmesh.android"))
        assertTrue(result.contains("ListenPort = 51820"))
        assertTrue(result.contains("DNS = 100.100.100.100"))
        assertTrue(result.contains("PersistentKeepalive = 25"))
        assertTrue(result.contains("PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="))
        assertFalse(result.contains("AllowedIPs = 0.0.0.0/0"))
        assertTrue(result.contains("11.0.0.0/8"))
    }

    @Test
    fun omitsEmptyExcludedApplication() {
        val json = """
            {"active":true,"privateKey":"key","addresses":["100.64.0.2/32"],
             "peers":[],"directRoutes":[],"blockRoutes":[]}
        """.trimIndent()
        val result = TunnelConfigParser.toWgQuick(json)
        assertFalse(result.contains("ExcludedApplications"))
    }

    @Test
    fun inactiveSnapshotDoesNotExposeAConfig() {
        val json = """{"version":8,"active":false}"""
        assertFalse(TunnelConfigParser.isActive(json))
        assertFalse(TunnelConfigParser.isReady(json))
        assertThrows(IllegalArgumentException::class.java) { TunnelConfigParser.toWgQuick(json) }
    }

    @Test
    fun waitsForFirstReconfigureAfterEngineUp() {
        val json = """{"version":1,"active":true,"privateKey":"","addresses":[],"peers":[]}"""
        assertTrue(TunnelConfigParser.isActive(json))
        assertFalse(TunnelConfigParser.isReady(json))
    }

    @Test
    fun rejectsBlockPolicyInsteadOfSilentlyLeakingTraffic() {
        val json = """
            {"active":true,"privateKey":"key","addresses":["100.64.0.2/32"],
             "peers":[],"directRoutes":[],"blockRoutes":["198.18.0.0/15"]}
        """.trimIndent()
        val error = assertThrows(IllegalArgumentException::class.java) {
            TunnelConfigParser.toWgQuick(json)
        }
        assertTrue(error.message.orEmpty().contains("blockRoutes"))
    }

    @Test
    fun capturesIpv6ForIpv4OnlyExitWithoutRejectingTunnel() {
        val json = """
            {"active":true,"privateKey":"key","addresses":["100.64.0.2/32"],
             "peers":[{"publicKey":"exit","allowedIPs":["100.64.0.3/32","0.0.0.0/0"]}],
             "directRoutes":[],"blockRoutes":["::/1","8000::/1"]}
        """.trimIndent()

        val result = TunnelConfigParser.toWgQuick(json)
        assertTrue(result.contains("AllowedIPs = "))
        assertTrue(result.contains("100.64.0.3/32"))
        assertTrue(result.contains("0.0.0.0/0"))
        assertTrue(result.contains("0:0:0:0:0:0:0:0/0"))
    }

    @Test
    fun omitsPeerWhoseRoutesAreEntirelyDirect() {
        val json = """
            {"active":true,"privateKey":"key","addresses":["100.64.0.2/32"],
             "peers":[{"publicKey":"peer","allowedIPs":["10.0.0.0/8"]}],
             "directRoutes":["10.0.0.0/8"],"blockRoutes":[]}
        """.trimIndent()
        val result = TunnelConfigParser.toWgQuick(json)
        assertFalse(result.contains("[Peer]"))
        assertFalse(result.contains("PublicKey = peer"))
    }

    @Test
    fun defersEndpointOnlyRefreshWhileExitIsHealthy() {
        val previous = """
            {"version":7,"active":true,"privateKey":"key","listenPort":51820,
             "addresses":["100.64.0.2/32"],"dnsServers":["1.1.1.1"],
             "peers":[{"publicKey":"exit","presharedKey":"psk",
             "endpoint":"203.0.113.4:51820","allowedIPs":["0.0.0.0/0"],
             "persistentKeepalive":5}],"directRoutes":[],"blockRoutes":[]}
        """.trimIndent()
        val next = previous
            .replace("\"version\":7", "\"version\":8")
            .replace("203.0.113.4:51820", "198.51.100.8:51820")

        assertFalse(TunnelConfigParser.requiresTunnelReplacement(previous, next))
        assertFalse(TunnelConfigParser.shouldApplyRefresh(previous, next, "home-exit", true))
        assertTrue(TunnelConfigParser.shouldApplyRefresh(previous, next, "home-exit", false))
        assertTrue(TunnelConfigParser.shouldApplyRefresh(previous, next, "", true))
    }

    @Test
    fun immediatelyAppliesRouteAndKeyChanges() {
        val previous = """
            {"active":true,"privateKey":"key","addresses":["100.64.0.2/32"],
             "peers":[{"publicKey":"peer","presharedKey":"old",
             "endpoint":"203.0.113.4:51820","allowedIPs":["100.64.0.3/32"]}],
             "directRoutes":[],"blockRoutes":[]}
        """.trimIndent()
        val routeChange = previous.replace("100.64.0.3/32", "0.0.0.0/0")
        val keyChange = previous.replace("\"old\"", "\"new\"")

        assertTrue(TunnelConfigParser.shouldApplyRefresh(previous, routeChange, "", true))
        assertTrue(TunnelConfigParser.shouldApplyRefresh(previous, keyChange, "", true))
    }
}
