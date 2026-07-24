package com.ratelmesh.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentConfigTest {
    @Test
    fun blankCoordinatorUsesOfficialService() {
        assertEquals(OFFICIAL_COORDINATOR_URL, normalizedCoordinator(""))
        assertEquals(OFFICIAL_COORDINATOR_URL, normalizedCoordinator("https://control.ratelmesh.com/"))
        assertTrue(validCoordinator(""))
    }

    @Test
    fun officialServiceRequiresOneUseEnrollmentCode() {
        assertTrue(validEnrollmentCode("ratelmesh-2345-6789-abcd", ""))
        assertFalse(validEnrollmentCode("legacy-secret", OFFICIAL_COORDINATOR_URL))
        assertFalse(validEnrollmentCode("", OFFICIAL_COORDINATOR_URL))
    }

    @Test
    fun customCoordinatorRemainsAvailableForSelfHostedNetworks() {
        assertTrue(validCoordinator("https://mesh.example.com"))
        assertTrue(validEnrollmentCode("self-hosted-key", "https://mesh.example.com"))
        assertFalse(validCoordinator("http://mesh.example.com"))
    }

    @Test
    fun deviceNamesMatchCoordinatorRules() {
        assertTrue(validDeviceName("pixel-9"))
        assertFalse(validDeviceName("pixel_9"))
        assertFalse(validDeviceName("-pixel"))
    }
}
