package com.ratelmesh.android.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MeshStateTest {
    @Test
    fun parsesVerifiedExitAndItsClients() {
        val state = parseStatus(
            """{"self":{"meshIP":"100.64.0.2"},"peers":[],"activeExit":"home-exit","selectedExit":"home-exit","exitTrafficVerified":true,"exitClients":[{"name":"phone","meshIP":"100.64.0.3","state":"active","online":true}]}""",
            MeshState(),
        )

        assertEquals("home-exit", state.activeExit)
        assertTrue(state.exitTrafficVerified)
        assertEquals("phone", state.exitClients.single().name)
        assertEquals("active", state.exitClients.single().state)
    }

    // A device that cannot complete registration used to sit on "Connecting…"
    // with no reason because parseStatus dropped the daemon's own signals. These
    // assertions pin that they are now surfaced so the UI can explain the failure.
    @Test
    fun surfacesBackendStateAndEnrollmentRequired() {
        val state = parseStatus(
            """{"state":"Starting","enrollmentRequired":true,"self":{"meshIP":""},"peers":[]}""",
            MeshState(),
        )
        assertEquals("Starting", state.backendState)
        assertTrue(state.enrollmentRequired)
    }

    @Test
    fun runningDeviceDoesNotFlagEnrollment() {
        val state = parseStatus(
            """{"state":"Running","enrollmentRequired":false,"self":{"meshIP":"100.64.0.4"},"peers":[]}""",
            MeshState(),
        )
        assertEquals("Running", state.backendState)
        assertFalse(state.enrollmentRequired)
    }

    @Test
    fun parsesTenantRemoteAccessGrant() {
        val state = parseStatus(
            """{"state":"Running","self":{"meshIP":"100.64.0.2"},"peers":[{"name":"office","meshIP":"100.64.0.8","role":"plain","online":true,"pathType":"direct","platform":"windows","remoteAccessAllowed":true,"remoteServices":[{"kind":"rdp","port":3389,"targetMeshIp":"100.64.0.8"},{"kind":"invalid","port":1,"targetMeshIp":"192.168.1.1"}]}]}""",
            MeshState(),
        )
        assertEquals("windows", state.peers.single().platform)
        assertTrue(state.peers.single().remoteAccessAllowed)
        assertEquals(listOf(RemoteService("rdp", 3389, "100.64.0.8")), state.peers.single().remoteServices)
    }
}
