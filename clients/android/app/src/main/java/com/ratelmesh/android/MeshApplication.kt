package com.ratelmesh.android

import android.app.Application
import android.app.ActivityManager
import android.os.Build
import com.ratelmesh.android.service.MeshVpnService
import com.wireguard.android.backend.GoBackend

class MeshApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Application is created in both the main and :meshcore processes. Do
        // not even initialize GoBackend in :meshcore: that process exclusively
        // owns RatelMeshMobile's Go runtime.
        if (!isMainProcess()) return
        GoBackend.setAlwaysOnCallback {
            // The system started WireGuard's VpnService, so restore the Go control
            // plane and foreground owner that will re-apply the current config.
            MeshVpnService.start(this)
        }
    }

    private fun isMainProcess(): Boolean {
        val processName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            getProcessName()
        } else {
            val pid = android.os.Process.myPid()
            getSystemService(ActivityManager::class.java)
                .runningAppProcesses
                ?.firstOrNull { it.pid == pid }
                ?.processName
        }
        return processName == packageName
    }
}
