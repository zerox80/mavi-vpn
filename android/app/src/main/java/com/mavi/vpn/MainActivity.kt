package com.mavi.vpn

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
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
import androidx.compose.runtime.collectAsState

import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.sp
import android.content.pm.PackageManager
import android.graphics.drawable.BitmapDrawable
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.foundation.clickable

class MainActivity : ComponentActivity() {

    private var lastIp = ""
    private var lastPort = ""
    private var lastToken = ""
    private var lastPin = ""

    private val vpnPrepareLauncher = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
             val prefs = getSharedPreferences("MaviVPN", Context.MODE_PRIVATE)
             val splitMode = prefs.getString("temp_split_mode", "exclude") ?: "exclude"
             val splitPackages = prefs.getString("temp_split_packages", "") ?: ""
             startVpnService(lastIp, lastPort, lastToken, lastPin, splitMode, splitPackages)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        requestBatteryOptimizationIgnore()
        
        // Load saved credentials
        val prefs = getSharedPreferences("MaviVPN", Context.MODE_PRIVATE)
        val savedIp = prefs.getString("saved_ip", "") ?: ""
        val savedPort = prefs.getString("saved_port", "4433") ?: "4433"
        val savedToken = prefs.getString("saved_token", "") ?: ""
        val savedPin = prefs.getString("saved_pin", "") ?: ""
        
        // Load Split Tunneling Prefs
        val savedSplitMode = prefs.getString("saved_split_mode", "exclude") ?: "exclude"
        val savedSplitPackages = prefs.getString("saved_split_packages", "") ?: ""

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
                    AppNavigation(
                        initialIp = savedIp,
                        initialPort = savedPort,
                        initialToken = savedToken,
                        initialPin = savedPin,
                        initialSplitMode = savedSplitMode,
                        initialSplitPackages = savedSplitPackages,
                        initialCensorshipResistant = prefs.getBoolean("saved_censorship_resistant", false),
                        onConnect = { ip, port, token, pin, splitMode, splitPackages -> 
                            // Save credentials
                            val editor = prefs.edit()
                            editor.putString("saved_ip", ip)
                            editor.putString("saved_port", port)
                            editor.putString("saved_token", token)
                            editor.putString("saved_pin", pin)
                            editor.putString("saved_split_mode", splitMode)
                            editor.putString("saved_split_packages", splitPackages)
                            editor.apply()
                            
                            prepareAndStartVpn(ip, port, token, pin, splitMode, splitPackages) 
                        },
                        onDisconnect = { stopVpn() },
                        context = this
                    )
                }
            }
        }
    }

    private fun prepareAndStartVpn(ip: String, port: String, token: String, pin: String, splitMode: String, splitPackages: String) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            lastIp = ip
            lastPort = port
            lastToken = token
            lastPin = pin
            // Hacky way to pass split config through result launcher, usually we'd use a ViewModel or Prefs refetch
            // But since we save to prefs before calling this, we can rely on startVpnService reading from prefs?
            // Actually startVpnService takes args. Let's update the class vars.
            // But wait, lastIp etc are used in the callback.
            // I'll update startVpnService to take new args too.
            getSharedPreferences("MaviVPN", Context.MODE_PRIVATE).edit()
                .putString("temp_split_mode", splitMode)
                .putString("temp_split_packages", splitPackages)
                .apply()
                
            vpnPrepareLauncher.launch(intent)
        } else {
            startVpnService(ip, port, token, pin, splitMode, splitPackages)
        }
    }
    
    // We need to update the callback
    // private var last... already defined.
    // I will modify the callback at the top of the class separately or just use prefs in the callback.
    
    private fun startVpnService(ip: String, port: String, token: String, pin: String, splitMode: String, splitPackages: String) {
        val intent = Intent(this, MaviVpnService::class.java).apply {
            action = "CONNECT"
            putExtra("IP", ip)
            putExtra("PORT", port)
            putExtra("TOKEN", token)
            putExtra("PIN", pin)
            putExtra("SPLIT_MODE", splitMode)
            putExtra("SPLIT_PACKAGES", splitPackages)
        }
        startService(intent)
    }

    private fun stopVpn() {
        val intent = Intent(this, MaviVpnService::class.java)
        intent.action = "STOP"
        startService(intent)
    }

    private fun requestBatteryOptimizationIgnore() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val intent = Intent()
            val packageName = packageName
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                intent.action = Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
                intent.data = Uri.parse("package:$packageName")
                startActivity(intent)
            }
        }
    }
}


@Composable
fun AppNavigation(
    initialIp: String,
    initialPort: String,
    initialToken: String,
    initialPin: String,
    initialSplitMode: String,
    initialSplitPackages: String,
    initialCensorshipResistant: Boolean,
    onConnect: (String, String, String, String, String, String) -> Unit,
    onDisconnect: () -> Unit,
    context: Context
) {
    var currentScreen by remember { mutableStateOf("home") }
    
    // State to hold settings between screens
    var splitMode by remember { mutableStateOf(initialSplitMode) }
    var splitPackages by remember { mutableStateOf(initialSplitPackages) }
    var censorshipResistant by remember { mutableStateOf(initialCensorshipResistant) }

    if (currentScreen == "home") {
        VpnScreen(
            initialIp = initialIp,
            initialPort = initialPort,
            initialToken = initialToken,
            initialPin = initialPin,
            onConnect = { ip, port, token, pin -> 
                // Save CR mode to prefs immediately (or rely on UI state if passed)
                // Actually startVpnService reads from prefs in Service, but we might want to pass it explicitly?
                // MaviVpnService reads "saved_censorship_resistant" from prefs. 
                // We should save it there when settings change or when connecting.
                // Let's save it when settings back is pressed.
                onConnect(ip, port, token, pin, splitMode, splitPackages)
            },
            onDisconnect = onDisconnect,
            onOpenSettings = { currentScreen = "settings" }
        )
    } else {
        SettingsScreen(
            context = context,
            initialMode = splitMode,
            initialSelection = splitPackages,
            initialCensorshipResistant = censorshipResistant,
            onBack = { mode, pkgs, crMode -> 
                splitMode = mode
                splitPackages = pkgs
                censorshipResistant = crMode
                
                // Save CR Mode to Prefs
                val prefs = context.getSharedPreferences("MaviVPN", Context.MODE_PRIVATE)
                prefs.edit().putBoolean("saved_censorship_resistant", crMode).apply()
                
                currentScreen = "home"
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnScreen(
    initialIp: String,
    initialPort: String,
    initialToken: String,
    initialPin: String,
    onConnect: (String, String, String, String) -> Unit, 
    onDisconnect: () -> Unit,
    onOpenSettings: () -> Unit
) {
    val isConnected by MaviVpnService.isConnected.collectAsState()
    var serverIp by remember { mutableStateOf(initialIp) }
    var serverPort by remember { mutableStateOf(initialPort) }
    var authToken by remember { mutableStateOf(initialToken) }
    var certPin by remember { mutableStateOf(initialPin) }

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
            modifier = Modifier
                .size(80.dp)
                .clickable { onOpenSettings() }, // Hidden shortcut? No, let's add a real button.
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

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = certPin,
                onValueChange = { certPin = it },
                label = { Text("Certificate PIN (SHA256 Hex)", color = Color.Gray) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                colors = TextFieldDefaults.outlinedTextFieldColors(
                    focusedBorderColor = Color(0xFF007AFF),
                    unfocusedBorderColor = Color.DarkGray,
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White
                )
            )
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Settings Button
            OutlinedButton(
                onClick = onOpenSettings,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color.White
                )
            ) {
                Text("Split Tunneling Settings")
            }

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
                } else {
                    if (serverIp.isNotEmpty() && authToken.isNotEmpty()) {
                        onConnect(serverIp, serverPort, authToken, certPin)
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

// --- App Selection Screen ---

data class InstalledApp(
    val name: String,
    val packageName: String,
    val icon: ImageBitmap?
)

@Composable
fun SettingsScreen(
    context: Context,
    initialMode: String, // "include" or "exclude"
    initialSelection: String, // comma separated packages
    initialCensorshipResistant: Boolean,
    onBack: (String, String, Boolean) -> Unit
) {
    var mode by remember { mutableStateOf(initialMode) } // "include", "exclude"
    var censorshipResistant by remember { mutableStateOf(initialCensorshipResistant) }
    
    val selectedPackages = remember { 
        mutableStateListOf<String>().apply { 
            addAll(initialSelection.split(",").map { it.trim() }.filter { it.isNotEmpty() })
        } 
    }
    
    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        // Load apps in background
        val appList = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
             // Basic fetch
             val pm = context.packageManager
             val packages = pm.getInstalledPackages(0)
             packages.mapNotNull { pkg ->
                 // Filter out system apps loosely (optimized for user apps)
                 val isSystem = (pkg.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                 // We show updated system apps too
                 val isUpdatedSystem = (pkg.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                 
                 // Show only if it has a launcher intent (user runnable)
                 val launchIntent = pm.getLaunchIntentForPackage(pkg.packageName)
                 
                 if (launchIntent != null && (!isSystem || isUpdatedSystem)) {
                     val iconDrawable = pkg.applicationInfo.loadIcon(pm)
                     val bitmap = (iconDrawable as? BitmapDrawable)?.bitmap
                     val imageBitmap = bitmap?.asImageBitmap()
                     
                     InstalledApp(
                         name = pkg.applicationInfo.loadLabel(pm).toString(),
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
        // Header
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 16.dp)
        ) {
            IconButton(onClick = { onBack(mode, selectedPackages.joinToString(","), censorshipResistant) }) {
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
        
        // --- Censorship Resistant Toggle ---
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1E1E1E), RoundedCornerShape(12.dp))
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Censorship Resistant Mode",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp
                )
                Text(
                    text = "Obfuscate traffic as HTTP/3 to bypass firewalls.",
                    color = Color.Gray,
                    fontSize = 12.sp
                )
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
        
        Spacer(modifier = Modifier.height(24.dp))
        
        Text(
            text = "Split Tunneling",
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
            color = Color.White,
            modifier = Modifier.padding(bottom = 12.dp)
        )
        
        // Mode Selection
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1E1E1E), RoundedCornerShape(8.dp))
                .padding(4.dp)
        ) {
            Button(
                onClick = { mode = "exclude" },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (mode == "exclude") Color(0xFF007AFF) else Color.Transparent
                ),
                shape = RoundedCornerShape(6.dp)
            ) {
                Text("Exclude Selected", color = Color.White)
            }
            Button(
                onClick = { mode = "include" },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (mode == "include") Color(0xFF007AFF) else Color.Transparent
                ),
                shape = RoundedCornerShape(6.dp)
            ) {
                Text("Include Selected", color = Color.White)
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = if (mode == "include") "Only selected apps will use VPN." else "Selected apps will bypass VPN.",
            color = Color.Gray,
            fontSize = 14.sp,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        // App List
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
                                if (isSelected) {
                                    selectedPackages.remove(app.packageName)
                                } else {
                                    selectedPackages.add(app.packageName)
                                }
                            }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        if (app.icon != null) {
                            androidx.compose.foundation.Image(
                                bitmap = app.icon, 
                                contentDescription = null, 
                                modifier = Modifier.size(40.dp)
                            )
                        } else {
                            Box(modifier = Modifier
                                .size(40.dp)
                                .background(Color.DarkGray, RoundedCornerShape(20.dp)))
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
                            colors = CheckboxDefaults.colors(
                                checkedColor = Color(0xFF007AFF),
                                uncheckedColor = Color.Gray,
                                checkmarkColor = Color.White
                            )
                        )
                    }
                    Divider(color = Color(0xFF2C2C2C))
                }
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = { onBack(mode, selectedPackages.joinToString(","), censorshipResistant) },
            modifier = Modifier.fillMaxWidth().height(50.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Save & Back", fontSize = 16.sp)
        }
    }
}
