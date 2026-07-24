package com.ratelmesh.android.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CidrRoutesTest {
    @Test
    fun removesSubnetFromDefaultRoute() {
        val result = CidrRoutes.subtract(listOf("0.0.0.0/0"), listOf("10.0.0.0/8"))
        assertFalse(result.contains("0.0.0.0/0"))
        assertFalse(result.any { it == "10.0.0.0/8" })
        assertTrue(result.contains("11.0.0.0/8"))
    }

    @Test
    fun leavesDifferentAddressFamilyAlone() {
        assertEquals(
            listOf("0:0:0:0:0:0:0:0/0"),
            CidrRoutes.subtract(listOf("::/0"), listOf("10.0.0.0/8")),
        )
    }
}
