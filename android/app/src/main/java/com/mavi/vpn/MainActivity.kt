package com.mavi.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    VpnScreen(onConnect = { prepareAndStartVpn() }, onDisconnect = { stopVpn() })
                }
            }
        }
    }

    private fun prepareAndStartVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, 0)
        } else {
            onActivityResult(0, Activity.RESULT_OK, null)
        }
    }

    private fun stopVpn() {
        val intent = Intent(this, MaviVpnService::class.java)
        intent.action = "STOP"
        startService(intent)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (resultCode == Activity.RESULT_OK) {
            val intent = Intent(this, MaviVpnService::class.java)
            intent.action = "CONNECT"
            startService(intent)
        }
        super.onActivityResult(requestCode, resultCode, data)
    }
}

@Composable
fun VpnScreen(onConnect: () -> Unit, onDisconnect: () -> Unit) {
    var isConnected by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = if (isConnected) "CONNECTED 🚀" else "DISCONNECTED",
            style = MaterialTheme.typography.headlineLarge,
            color = if (isConnected) Color.Green else Color.Red
        )
        Spacer(modifier = Modifier.height(32.dp))
        Button(
            onClick = {
                if (isConnected) {
                    onDisconnect()
                    isConnected = false
                } else {
                    onConnect()
                    isConnected = true
                }
            },
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isConnected) Color.Red else Color.Blue
            )
        ) {
            Text(text = if (isConnected) "DISCONNECT" else "CONNECT")
        }
    }
}
