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

import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.sp

class MainActivity : ComponentActivity() {

    private var lastIp = ""
    private var lastPort = ""
    private var lastToken = ""

    private val vpnPrepareLauncher = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
             startVpnService(lastIp, lastPort, lastToken)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF007AFF),
                    background = Color(0xFF121212),
                    surface = Color(0xFF1E1E1E)
                )
            ) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    VpnScreen(
                        onConnect = { ip, port, token -> prepareAndStartVpn(ip, port, token) },
                        onDisconnect = { stopVpn() }
                    )
                }
            }
        }
    }

    private fun prepareAndStartVpn(ip: String, port: String, token: String) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            lastIp = ip
            lastPort = port
            lastToken = token
            vpnPrepareLauncher.launch(intent)
        } else {
            startVpnService(ip, port, token)
        }
    }

    private fun startVpnService(ip: String, port: String, token: String) {
        val intent = Intent(this, MaviVpnService::class.java).apply {
            action = "CONNECT"
            putExtra("IP", ip)
            putExtra("PORT", port)
            putExtra("TOKEN", token)
        }
        startService(intent)
    }

    private fun stopVpn() {
        val intent = Intent(this, MaviVpnService::class.java)
        intent.action = "STOP"
        startService(intent)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnScreen(onConnect: (String, String, String) -> Unit, onDisconnect: () -> Unit) {
    var isConnected by remember { mutableStateOf(false) }
    var serverIp by remember { mutableStateOf("") }
    var serverPort by remember { mutableStateOf("4433") }
    var authToken by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top
    ) {
        Spacer(modifier = Modifier.height(48.dp))
        
        Icon(
            imageVector = if (isConnected) Icons.Default.Lock else Icons.Default.Settings,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = if (isConnected) Color(0xFF00FF7F) else Color(0xFF007AFF)
        )
        
        Spacer(modifier = Modifier.height(24.dp))
        
        Text(
            text = "MAVI VPN",
            fontSize = 32.sp,
            fontWeight = FontWeight.Bold,
            color = Color.White
        )
        
        Text(
            text = if (isConnected) "SECURED CONNECTION" else "READY TO CONNECT",
            fontSize = 14.sp,
            color = if (isConnected) Color(0xFF00FF7F) else Color.Gray
        )

        Spacer(modifier = Modifier.height(48.dp))

        if (!isConnected) {
            OutlinedTextField(
                value = serverIp,
                onValueChange = { serverIp = it },
                label = { Text("Server IP", color = Color.Gray) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                colors = TextFieldDefaults.outlinedTextFieldColors(
                    focusedBorderColor = Color(0xFF007AFF),
                    unfocusedBorderColor = Color.DarkGray,
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White
                )
            )

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = serverPort,
                onValueChange = { serverPort = it },
                label = { Text("Port", color = Color.Gray) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                colors = TextFieldDefaults.outlinedTextFieldColors(
                    focusedBorderColor = Color(0xFF007AFF),
                    unfocusedBorderColor = Color.DarkGray,
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White
                )
            )

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = authToken,
                onValueChange = { authToken = it },
                label = { Text("Auth Token", color = Color.Gray) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                colors = TextFieldDefaults.outlinedTextFieldColors(
                    focusedBorderColor = Color(0xFF007AFF),
                    unfocusedBorderColor = Color.DarkGray,
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White
                )
            )
        } else {
            // Stats or connection info could go here
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF1E1E1E), RoundedCornerShape(12.dp))
                    .padding(24.dp)
            ) {
                Column {
                    Text("Connected to:", color = Color.Gray, fontSize = 12.sp)
                    Text(serverIp, color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Medium)
                }
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        Button(
            onClick = {
                if (isConnected) {
                    onDisconnect()
                    isConnected = false
                } else {
                    if (serverIp.isNotEmpty() && authToken.isNotEmpty()) {
                        onConnect(serverIp, serverPort, authToken)
                        isConnected = true
                    }
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isConnected) Color(0xFFFF3B30) else Color(0xFF007AFF)
            )
        ) {
            Text(
                text = if (isConnected) "DISCONNECT" else "CONNECT",
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
        }
        
        Spacer(modifier = Modifier.height(24.dp))
    }
}
