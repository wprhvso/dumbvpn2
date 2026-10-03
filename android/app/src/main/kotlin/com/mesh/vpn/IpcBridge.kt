package com.mesh.vpn

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.FileDescriptor

object IpcBridge {
    fun passFd(socketPath: String, fd: FileDescriptor) {
        val socket = LocalSocket()
        socket.connect(LocalSocketAddress(socketPath, LocalSocketAddress.Namespace.FILESYSTEM))
        socket.setFileDescriptorsForSend(arrayOf(fd))
        socket.outputStream.write(byteArrayOf(1))
        socket.close()
    }
}
