package com.mavi.vpn.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mavi.vpn.MainActivity
import com.mavi.vpn.viewmodel.VpnViewModel

@Composable
fun SettingsScreen(
    viewModel: VpnViewModel,
    onBack: (String, String, Boolean, Boolean, Boolean, Int) -> Unit,
    onOpenSplitTunneling: () -> Unit,
) {
    val context = LocalContext.current
    
    val initialMode by viewModel.splitMode.collectAsState()
    val initialSelection by viewModel.splitPackages.collectAsState()
    val initialCensorshipResistant by viewModel.censorshipResistant.collectAsState()
    val initialHttp3Framing by viewModel.http3Framing.collectAsState()
    val initialHttp2Framing by viewModel.http2Framing.collectAsState()
    val initialVpnMtu by viewModel.vpnMtu.collectAsState()
    
    var censorshipResistant by remember { mutableStateOf(initialCensorshipResistant) }
    var http3Framing by remember { mutableStateOf(initialHttp3Framing) }
    var http2Framing by remember { mutableStateOf(initialHttp2Framing) }
    var vpnMtuText by remember { mutableStateOf(if (initialVpnMtu > 0) initialVpnMtu.toString() else "") }

    fun parseValidatedMtu(): Int? {
        if (vpnMtuText.isBlank()) return 0
        val value = vpnMtuText.toIntOrNull() ?: return null
        if (value !in 1280..1360) {
            Toast.makeText(context, "VPN MTU must be between 1280 and 1360", Toast.LENGTH_SHORT).show()
            return null
        }
        return value
    }
    
    fun saveAndBack() {
        val mtu = parseValidatedMtu() ?: return
        onBack(
            initialMode,
            initialSelection,
            censorshipResistant,
            http3Framing,
            http2Framing,
            mtu,
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF121212))
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp)
        ) {
            IconButton(onClick = { saveAndBack() }) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = Color.White)
            }
            Text(
                text = "Settings",
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White,
                modifier = Modifier.padding(start = 8.dp)
            )
        }
        
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1E1E1E), RoundedCornerShape(12.dp))
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = "Censorship Resistant Mode", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(text = "Obfuscate traffic as HTTP/3 to bypass firewalls.", color = Color.Gray, fontSize = 12.sp)
            }
            Switch(
                checked = censorshipResistant,
                onCheckedChange = {
                    censorshipResistant = it
                    if (it) {
                        http3Framing = true
                        http2Framing = false
                    }
                },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = Color(0xFF007AFF),
                    uncheckedThumbColor = Color.Gray,
                    uncheckedTrackColor = Color.DarkGray
                )
            )
        }
        
        Spacer(modifier = Modifier.height(16.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1E1E1E), RoundedCornerShape(12.dp))
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = "HTTP/3 Framing", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(text = "Tunnel packets inside HTTP/3 datagrams (RFC 9297).", color = Color.Gray, fontSize = 12.sp)
            }
            Switch(
                checked = http3Framing,
                onCheckedChange = {
                    http3Framing = it
                    if (it) http2Framing = false
                    if (!it) censorshipResistant = false
                },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = Color(0xFF007AFF),
                    uncheckedThumbColor = Color.Gray,
                    uncheckedTrackColor = Color.DarkGray
                )
            )
        }
        
        Spacer(modifier = Modifier.height(16.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1E1E1E), RoundedCornerShape(12.dp))
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = "HTTP/2 CONNECT-IP", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(text = "Tunnel over TLS/TCP using HTTP/2 and RFC 9297 capsules.", color = Color.Gray, fontSize = 12.sp)
            }
            Switch(
                checked = http2Framing,
                onCheckedChange = {
                    http2Framing = it
                    if (it) {
                        censorshipResistant = false
                        http3Framing = false
                    }
                },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = Color(0xFF007AFF),
                    uncheckedThumbColor = Color.Gray,
                    uncheckedTrackColor = Color.DarkGray,
                ),
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1E1E1E), RoundedCornerShape(12.dp))
                .padding(16.dp)
        ) {
            Text(text = "VPN MTU", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            Text(text = "Inner TUN MTU (1280–1360). Default: 1280. Must match server.", color = Color.Gray, fontSize = 12.sp)
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = vpnMtuText,
                onValueChange = { vpnMtuText = it.filter { c -> c.isDigit() } },
                placeholder = { Text("1280", color = Color.Gray) },
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    focusedBorderColor = Color(0xFF007AFF),
                    unfocusedBorderColor = Color.DarkGray
                ),
                modifier = Modifier.fillMaxWidth()
            )
        }
        
        Spacer(modifier = Modifier.height(16.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1E1E1E), RoundedCornerShape(12.dp))
                .clickable {
                    (context as? MainActivity)?.requestBatteryOptimizationIgnore()
                }
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = "Battery Optimization", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(text = "Ensure the VPN is not killed in the background.", color = Color.Gray, fontSize = 12.sp)
            }
            Icon(Icons.Default.Lock, contentDescription = null, tint = Color.Gray, modifier = Modifier.size(24.dp))
        }
        
        Spacer(modifier = Modifier.height(16.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1E1E1E), RoundedCornerShape(12.dp))
                .clickable(onClick = onOpenSplitTunneling)
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = "Split Tunneling", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                val selectedCount = initialSelection.split(",").count { it.isNotBlank() }
                val modeLabel = if (initialMode == "include") "Only selected apps use VPN" else "Selected apps bypass VPN"
                Text(text = "$modeLabel · $selectedCount selected", color = Color.Gray, fontSize = 12.sp)
            }
            Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = "Open split tunneling", tint = Color.Gray)
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = { saveAndBack() },
            modifier = Modifier.fillMaxWidth().height(50.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Save & Back", fontSize = 16.sp)
        }
    }
}
