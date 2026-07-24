package com.ratelmesh.android.service

import org.json.JSONObject

/** Builds the gomobile control-plane options used by Android. */
internal fun meshCoreOptions(
    coordinatorUrl: String,
    authKey: String,
    stateDirectory: String,
    hostname: String,
    listenPort: Int = 51820,
    endpointCandidatesJson: String = "[]",
    // coordTransport ("wss") carries the coordinator connection inside a
    // camouflage transport for censored networks (e.g. reaching a Cloudflare-fronted
    // coordinator from inside the GFW); empty keeps plain HTTPS. coordFrontDoor is
    // the host:port that transport dials, defaulting to the coordinator host on :443.
    coordTransport: String = "",
    coordFrontDoor: String = "",
): String = JSONObject()
    .put("coordURL", coordinatorUrl)
    .put("authKey", authKey)
    .put("stateDir", stateDirectory)
    .put("hostname", hostname)
    .apply {
        if (coordTransport.isNotBlank()) put("coordTransport", coordTransport)
        if (coordFrontDoor.isNotBlank()) put("coordFrontDoor", coordFrontDoor)
    }
    // Keep the native WireGuard socket stable across reconnects and publish the
    // STUN mapping learned from this same local port immediately before startup.
    .put("listenPort", listenPort)
    .put("endpoints", org.json.JSONArray(endpointCandidatesJson))
    // Do not inherit the physical network's resolver. In restricted networks it
    // can poison dual-stack destinations before their traffic enters the VPN.
    // These queries follow the exit's default route and are resolved abroad.
    .put("dnsServers", org.json.JSONArray(listOf("1.1.1.1", "8.8.8.8")))
    // Use direct peer endpoints unless a tenant relay is actually advertised.
    // ForceRelay with no configured relay deliberately removes every endpoint
    // (fail closed), which made the official relay-free service unable to
    // handshake with any peer or EXIT.
    .put("forceRelay", false)
    .toString()
