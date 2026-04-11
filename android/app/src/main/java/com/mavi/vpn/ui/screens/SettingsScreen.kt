package com.mavi.vpn.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mavi.vpn.MainActivity
import com.mavi.vpn.data.InstalledApp
import com.mavi.vpn.ui.components.drawableToBitmap
import com.mavi.vpn.ui.components.toImageBitmap
import com.mavi.vpn.viewmodel.VpnViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun SettingsScreen(
    viewModel: VpnViewModel,
    onBack: (String, String, Boolean, Boolean) -> Unit
) {
    val context = LocalContext.current
    
    val initialMode by viewModel.splitMode.collectAsState()
    val initialSelection by viewModel.splitPackages.collectAsState()
    val initialCensorshipResistant by viewModel.censorshipResistant.collectAsState()
    val initialHttp3Framing by viewModel.http3Framing.collectAsState()
    
    var mode by remember { mutableStateOf(initialMode) }
    var censorshipResistant by remember { mutableStateOf(initialCensorshipResistant) }
    var http3Framing by remember { mutableStateOf(initialHttp3Framing) }
    
    val selectedPackages = remember { 
        mutableStateListOf<String>().apply { 
            addAll(initialSelection.split(",").map { it.trim() }.filter { it.isNotEmpty() })
        } 
    }
    
    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        val appList = withContext(Dispatchers.IO) {
             val pm = context.packageManager
             val packages = pm.getInstalledPackages(0)
             packages.mapNotNull { pkg ->
                 val appInfo = pkg.applicationInfo ?: return@mapNotNull null
                 val isSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                 val isUpdatedSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                 val launchIntent = pm.getLaunchIntentForPackage(pkg.packageName)
                 
                 if (launchIntent != null && (!isSystem || isUpdatedSystem)) {
                     val iconDrawable = appInfo.loadIcon(pm)
                     val imageBitmap = drawableToBitmap(iconDrawable)?.toImageBitmap()
                     
                     InstalledApp(
                         name = appInfo.loadLabel(pm).toString(),
                         packageName = pkg.packageName,
                         icon = imageBitmap
                     )
                 } else {
                     null
                 }
             }.sortedBy { it.name.lowercase() }
        }
        apps = appList
        isLoading = false
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF121212))
            .padding(16.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp)
        ) {
            IconButton(onClick = { onBack(mode, selectedPackages.joinToString(","), censorshipResistant, http3Framing) }) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color.White)
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
                onCheckedChange = { censorshipResistant = it },
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
                onCheckedChange = { http3Framing = it },
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
        
        Spacer(modifier = Modifier.height(24.dp))
        
        Text(text = "Split Tunneling", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.padding(bottom = 12.dp))
        
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1E1E1E), RoundedCornerShape(8.dp))
                .padding(4.dp)
        ) {
            Button(
                onClick = { mode = "exclude" },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = if (mode == "exclude") Color(0xFF007AFF) else Color.Transparent),
                shape = RoundedCornerShape(6.dp)
            ) {
                Text("Exclude Selected", color = Color.White)
            }
            Button(
                onClick = { mode = "include" },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = if (mode == "include") Color(0xFF007AFF) else Color.Transparent),
                shape = RoundedCornerShape(6.dp)
            ) {
                Text("Include Selected", color = Color.White)
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        Text(text = if (mode == "include") "Only selected apps will use VPN." else "Selected apps will bypass VPN.", color = Color.Gray, fontSize = 14.sp, modifier = Modifier.padding(bottom = 8.dp))

        if (isLoading) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = Color(0xFF007AFF))
            }
        } else {
            LazyColumn(modifier = Modifier.weight(1f)) {
                items(apps) { app ->
                    val isSelected = selectedPackages.contains(app.packageName)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                if (isSelected) selectedPackages.remove(app.packageName) else selectedPackages.add(app.packageName)
                            }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        if (app.icon != null) {
                            androidx.compose.foundation.Image(bitmap = app.icon, contentDescription = null, modifier = Modifier.size(40.dp))
                        } else {
                            Box(modifier = Modifier.size(40.dp).background(Color.DarkGray, RoundedCornerShape(20.dp)))
                        }
                        
                        Spacer(modifier = Modifier.width(16.dp))
                        
                        Column(modifier = Modifier.weight(1f)) {
                            Text(text = app.name, color = Color.White, fontWeight = FontWeight.Medium)
                            Text(text = app.packageName, color = Color.Gray, fontSize = 12.sp)
                        }
                        
                        Checkbox(
                            checked = isSelected,
                            onCheckedChange = { checked ->
                                if (checked) selectedPackages.add(app.packageName) else selectedPackages.remove(app.packageName)
                            },
                            colors = CheckboxDefaults.colors(checkedColor = Color(0xFF007AFF), uncheckedColor = Color.Gray, checkmarkColor = Color.White)
                        )
                    }
                    Divider(color = Color(0xFF2C2C2C))
                }
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = { onBack(mode, selectedPackages.joinToString(","), censorshipResistant, http3Framing) },
            modifier = Modifier.fillMaxWidth().height(50.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Save & Back", fontSize = 16.sp)
        }
    }
}
