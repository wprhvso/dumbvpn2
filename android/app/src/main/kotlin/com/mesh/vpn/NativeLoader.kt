package com.mesh.vpn

import android.content.Context
import java.io.File

object NativeLoader {
    external fun startEngine(tunFd: Int): Int
    external fun stopEngine()

    fun load(context: Context) {
        val updatedLib = File(context.filesDir, "libcore.so")
        if (updatedLib.exists()) {
            System.load(updatedLib.absolutePath)
        } else {
            System.loadLibrary("core")
        }
    }
}
