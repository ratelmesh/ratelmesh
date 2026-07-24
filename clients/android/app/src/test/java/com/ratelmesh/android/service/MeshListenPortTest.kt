package com.ratelmesh.android.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MeshListenPortTest {
    @Test
    fun generatedPortsStayInsideThePrivateApplicationRange() {
        assertEquals(MeshListenPort.MIN, MeshListenPort.fromEntropy(0))
        assertEquals(MeshListenPort.MAX, MeshListenPort.fromEntropy(19_999))
    }

    @Test
    fun onlyPersistedApplicationPortsAreReused() {
        assertTrue(MeshListenPort.isValid(MeshListenPort.MIN))
        assertTrue(MeshListenPort.isValid(MeshListenPort.MAX))
        assertFalse(MeshListenPort.isValid(51820))
        assertFalse(MeshListenPort.isValid(0))
    }
}
