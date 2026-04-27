package com.mavi.vpn.ui.screens

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.util.LruCache
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Share
import androidx.core.content.FileProvider
import java.io.File
import java.io.FileOutputStream
import kotlinx.coroutines.launch
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mavi.vpn.MainActivity
import com.mavi.vpn.data.InstalledApp
import com.mavi.vpn.ui.components.drawableToBitmap
import com.mavi.vpn.ui.components.toImageBitmap
import com.mavi.vpn.viewmodel.VpnViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

private val appIconCache = LruCache<String, ImageBitmap>(256)
private val appIconLoadLimiter = Semaphore(4)

@Composable
fun SettingsScreen(
    viewModel: VpnViewModel,
    onBack: (String, String, Boolean, Boolean, Int, Boolean) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    val initialMode by viewModel.splitMode.collectAsState()
    val initialSelection by viewModel.splitPackages.collectAsState()
    val initialCensorshipResistant by viewModel.censorshipResistant.collectAsState()
    val initialHttp3Framing by viewModel.http3Framing.collectAsState()
    val initialVpnMtu by viewModel.vpnMtu.collectAsState()
    val initialEnableLogging by viewModel.enableLogging.collectAsState()
    
    var mode by remember { mutableStateOf(initialMode) }
    var censorshipResistant by remember { mutableStateOf(initialCensorshipResistant) }
    var http3Framing by remember { mutableStateOf(initialHttp3Framing) }
    var vpnMtuText by remember { mutableStateOf(if (initialVpnMtu > 0) initialVpnMtu.toString() else "") }
    var enableLogging by remember { mutableStateOf(initialEnableLogging) }

    fun parseValidatedMtu(): Int {
        if (vpnMtuText.isBlank()) return 0
        val value = vpnMtuText.toIntOrNull() ?: return 0
        if (value !in 1280..1360) {
            Toast.makeText(context, "VPN MTU must be between 1280 and 1360", Toast.LENGTH_SHORT).show()
            return 0
        }
        return value
    }
    
    val selectedPackages = remember {
        mutableStateMapOf<String, Boolean>().apply {
            initialSelection
                .split(",")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .forEach { this[it] = true }
        }
    }
    
    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        val appList = withContext(Dispatchers.IO) {
             val pm = context.packageManager
             val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
             val seenPackages = HashSet<String>()

             pm.queryIntentActivities(launcherIntent, 0).mapNotNull { resolveInfo ->
                 val appInfo = resolveInfo.activityInfo?.applicationInfo ?: return@mapNotNull null
                 val packageName = appInfo.packageName
                 if (!seenPackages.add(packageName)) {
                     return@mapNotNull null
                 }

                 val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                 val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

                 if (!isSystem || isUpdatedSystem) {
                     InstalledApp(
                         name = appInfo.loadLabel(pm).toString(),
                         packageName = packageName
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
            IconButton(onClick = { onBack(mode, selectedPackages.keys.joinToString(","), censorshipResistant, http3Framing, parseValidatedMtu(), enableLogging) }) {
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
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = "Enable Debug Logging", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(text = "Logs VPN events for troubleshooting. Disable for privacy.", color = Color.Gray, fontSize = 12.sp)
            }
            Switch(
                checked = enableLogging,
                onCheckedChange = {
                    enableLogging = it
                    viewModel.setEnableLogging(it)
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
                .clickable {
                    if (!enableLogging) {
                        Toast.makeText(context, "Enable debug logging before exporting logs.", Toast.LENGTH_SHORT).show()
                        return@clickable
                    }
                    scope.launch(Dispatchers.IO) {
                        try {
                            val logDir = File(context.cacheDir, "logs")
                            if (!logDir.exists()) logDir.mkdirs()
                            val logFile = File(logDir, "mavivpn_log.txt")
                            val process = Runtime.getRuntime().exec(
                                arrayOf(
                                    "logcat",
                                    "-d",
                                    "-v",
                                    "threadtime",
                                    "-s",
                                    "MaviVPN:*",
                                    "OAuthHelper:*",
                                )
                            )
                            process.inputStream.use { input ->
                                FileOutputStream(logFile).use { output ->
                                    input.copyTo(output)
                                }
                            }
                            process.waitFor()
                            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", logFile)
                            val intent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_STREAM, uri)
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }
                            withContext(Dispatchers.Main) {
                                context.startActivity(Intent.createChooser(intent, "Share Logs"))
                            }
                        } catch (e: Exception) {
                            withContext(Dispatchers.Main) {
                                Toast.makeText(context, "Failed to export logs: ${e.message}", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = "Export Logs", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(text = "Requires debug logging to be enabled.", color = Color.Gray, fontSize = 12.sp)
            }
            Icon(Icons.Default.Share, contentDescription = null, tint = Color.Gray, modifier = Modifier.size(24.dp))
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
                items(apps, key = { it.packageName }) { app ->
                    val isSelected = selectedPackages.containsKey(app.packageName)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                if (isSelected) selectedPackages.remove(app.packageName) else selectedPackages[app.packageName] = true
                            }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        InstalledAppIcon(packageName = app.packageName)
                        
                        Spacer(modifier = Modifier.width(16.dp))
                        
                        Column(modifier = Modifier.weight(1f)) {
                            Text(text = app.name, color = Color.White, fontWeight = FontWeight.Medium)
                            Text(text = app.packageName, color = Color.Gray, fontSize = 12.sp)
                        }
                        
                        Checkbox(
                            checked = isSelected,
                            onCheckedChange = { checked ->
                                if (checked) selectedPackages[app.packageName] = true else selectedPackages.remove(app.packageName)
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
            onClick = { onBack(mode, selectedPackages.keys.joinToString(","), censorshipResistant, http3Framing, parseValidatedMtu(), enableLogging) },
            modifier = Modifier.fillMaxWidth().height(50.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Save & Back", fontSize = 16.sp)
        }
    }
}

@Composable
private fun InstalledAppIcon(packageName: String) {
    val context = LocalContext.current.applicationContext
    val iconSizePx = with(LocalDensity.current) { 40.dp.roundToPx() }
    val cacheKey = "$packageName:$iconSizePx"
    var icon by remember(cacheKey) { mutableStateOf<ImageBitmap?>(appIconCache.get(cacheKey)) }

    LaunchedEffect(cacheKey) {
        if (icon != null) {
            return@LaunchedEffect
        }
        icon = withContext(Dispatchers.IO) {
            appIconLoadLimiter.withPermit {
                runCatching {
                    val drawable = context.packageManager.getApplicationIcon(packageName)
                    drawableToBitmap(drawable, iconSizePx)?.toImageBitmap()?.also {
                        appIconCache.put(cacheKey, it)
                    }
                }.getOrNull()
            }
        }
    }

    if (icon != null) {
        androidx.compose.foundation.Image(bitmap = icon!!, contentDescription = null, modifier = Modifier.size(40.dp))
    } else {
        Box(modifier = Modifier.size(40.dp).background(Color.DarkGray, RoundedCornerShape(20.dp)))
    }
}
