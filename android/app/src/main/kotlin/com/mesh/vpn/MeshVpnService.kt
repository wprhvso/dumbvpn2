package com.mesh.vpn

import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor

class MeshVpnService : VpnService() {
    private var pfd: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val builder = Builder()
            .setMtu(1500)
            .addAddress("10.88.0.2", 16)
            .addRoute("198.18.0.0", 15)
            .addDnsServer("198.18.0.1")

        pfd = builder.establish()
        pfd?.let {
            NativeLoader.load(this)
            NativeLoader.startEngine(it.fd)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        NativeLoader.stopEngine()
        pfd?.close()
        super.onDestroy()
    }
}
