package com.ratelmesh.android.service

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class MeshCoreOptionsTest {
    @Test
    fun androidKeepsDirectEndpointsWhenNoRelayIsConfigured() {
        val options = JSONObject(
            meshCoreOptions(
                coordinatorUrl = "https://coord.example",
                authKey = "one-time-code",
                stateDirectory = "/data/state",
                hostname = "phone",
                listenPort = 47_321,
                endpointCandidatesJson = "[\"203.0.113.9:41123\"]",
            ),
        )

        assertEquals("https://coord.example", options.getString("coordURL"))
        assertEquals("one-time-code", options.getString("authKey"))
        assertEquals("/data/state", options.getString("stateDir"))
        assertEquals("phone", options.getString("hostname"))
        assertFalse(options.getBoolean("forceRelay"))
        assertEquals(47_321, options.getInt("listenPort"))
        assertEquals("203.0.113.9:41123", options.getJSONArray("endpoints").getString(0))
        assertEquals("1.1.1.1", options.getJSONArray("dnsServers").getString(0))
        assertEquals("8.8.8.8", options.getJSONArray("dnsServers").getString(1))
        // Camouflage is opt-in: absent unless explicitly configured.
        assertFalse(options.has("coordTransport"))
        assertFalse(options.has("coordFrontDoor"))
    }

    @Test
    fun carriesCoordinatorCamouflageWhenConfigured() {
        val options = JSONObject(
            meshCoreOptions(
                coordinatorUrl = "https://control.ratelmesh.com",
                authKey = "one-time-code",
                stateDirectory = "/data/state",
                hostname = "phone",
                coordTransport = "wss",
                coordFrontDoor = "edge.example.net:443",
            ),
        )

        assertEquals("wss", options.getString("coordTransport"))
        assertEquals("edge.example.net:443", options.getString("coordFrontDoor"))
    }
}
