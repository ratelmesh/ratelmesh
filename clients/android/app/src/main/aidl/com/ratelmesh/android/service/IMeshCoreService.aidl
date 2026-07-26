package com.ratelmesh.android.service;

/**
 * Process boundary between RatelMeshMobile's Go runtime and WireGuard's GoBackend.
 *
 * Android cannot safely load both Go shared libraries in one process. Keep this
 * interface primitive-only so the VPN process never references RatelMeshMobile types.
 */
interface IMeshCoreService {
    String startApp(String coordinatorUrl, String authKey, String stateDirectory, String hostname, int listenPort, String endpointCandidatesJson);
    void stopApp();
    long tunnelConfigVersion();
    String tunnelConfigJSON();
    String statusJSON();
    String publicKey();
    String lastError();
    void updatePeerStatsJSON(String payload);
    String useExit(String name);
    String clearExit();
	String setSystemLocation(double latitude, double longitude);
    String doctorDisclosureVersion();
    String runNetworkDoctor(String disclosureVersion, boolean confirmed);
    String applyNetworkDoctorRepair(String planID, String action, String disclosureVersion, boolean confirmed);
}
