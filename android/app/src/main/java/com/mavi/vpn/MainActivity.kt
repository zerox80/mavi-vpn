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
import androidx.compose.ui.platform.LocalContext

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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

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
                        initialTransportMode = prefs.getInt("saved_transport_mode", 0),
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
                        onDisconnect = { stopVpn() }
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
    
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        val data: Uri? = intent.data
        if (data != null && data.scheme == "mavivpn" && data.host == "oauth") {
            val code = data.getQueryParameter("code")
            if (code != null) {
                // Clear the data so it's not processed again on potentially relaunch/recreate
                intent.setData(null)
                
                val prefs = getSharedPreferences("MaviVPN", Context.MODE_PRIVATE)
                val kcUrl = prefs.getString("saved_kc_url", "") ?: ""
                val realm = prefs.getString("saved_kc_realm", "mavi-vpn") ?: "mavi-vpn"
                val clientId = prefs.getString("saved_kc_client_id", "mavi-client") ?: "mavi-client"
                
                // Start a coroutine to exchange token
                lifecycleScope.launch {
                    val token = OAuthHelper.exchangeCodeForToken(code, kcUrl, realm, clientId)
                    if (token != null) {
                        prefs.edit().putString("saved_token", token).apply()
                        // Restart the UI with the new token
                        recreate()
                    }
                }
            }
        }
    }

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

    fun requestBatteryOptimizationIgnore() {
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
    initialTransportMode: Int, // 0=QUIC, 1=HTTP/3, 2=HTTP/2
    onConnect: (String, String, String, String, String, String) -> Unit,
    onDisconnect: () -> Unit
) {
    val context = LocalContext.current
    var currentScreen by remember { mutableStateOf<String>("home") }
    
    // State to hold settings between screens
    var splitMode by remember { mutableStateOf<String>(initialSplitMode) }
    var splitPackages by remember { mutableStateOf<String>(initialSplitPackages) }
    var transportMode by remember { mutableStateOf<Int>(initialTransportMode) }

    if (currentScreen == "home") {
        VpnScreen(
            initialIp = initialIp,
            initialPort = initialPort,
            initialToken = initialToken,
            initialPin = initialPin,
            onConnect = { ip, port, token, pin -> 
                onConnect(ip, port, token, pin, splitMode, splitPackages)
            },
            onDisconnect = onDisconnect,
            onOpenSettings = { currentScreen = "settings" }
        )
    } else {
        SettingsScreen(
            initialMode = splitMode,
            initialSelection = splitPackages,
            initialTransportMode = transportMode,
            onBack = { mode, pkgs, tMode ->
                splitMode = mode
                splitPackages = pkgs
                transportMode = tMode

                // Save Transport Mode to Prefs
                val prefs = context.getSharedPreferences("MaviVPN", Context.MODE_PRIVATE)
                prefs.edit().putInt("saved_transport_mode", tMode).apply()
                
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
    val context = LocalContext.current
    val isConnected by MaviVpnService.isConnected.collectAsState()
    var serverIp by remember { mutableStateOf<String>(initialIp) }
    var serverPort by remember { mutableStateOf<String>(initialPort) }
    var authToken by remember { mutableStateOf<String>(initialToken) }
    var certPin by remember { mutableStateOf<String>(initialPin) }
    
    // Keycloak & auth mode state
    val prefs = context.getSharedPreferences("MaviVPN", Context.MODE_PRIVATE)
    var useKeycloak by remember { mutableStateOf(prefs.getBoolean("saved_use_keycloak", false)) }
    var kcUrl by remember { mutableStateOf<String>(prefs.getString("saved_kc_url", "") ?: "") }
    var kcRealm by remember { mutableStateOf<String>(prefs.getString("saved_kc_realm", "mavi-vpn") ?: "mavi-vpn") }
    var kcClientId by remember { mutableStateOf<String>(prefs.getString("saved_kc_client_id", "mavi-client") ?: "mavi-client") }
    var errorMessage by remember { mutableStateOf("") }

    val fieldColors = OutlinedTextFieldDefaults.colors(
        focusedBorderColor = Color(0xFF007AFF),
        unfocusedBorderColor = Color.DarkGray,
        focusedTextColor = Color.White,
        unfocusedTextColor = Color.White
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Scrollable content area
        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(48.dp))

            Icon(
                imageVector = if (isConnected) Icons.Default.Lock else Icons.Default.Settings,
                contentDescription = null,
                modifier = Modifier
                    .size(80.dp)
                    .clickable { onOpenSettings() },
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

            Spacer(modifier = Modifier.height(32.dp))

            if (!isConnected) {
            // --- Server fields (always visible) ---
            OutlinedTextField(
                value = serverIp,
                onValueChange = { serverIp = it },
                label = { Text("Server IP / Endpoint", color = Color.Gray) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                colors = fieldColors
            )

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = serverPort,
                onValueChange = { serverPort = it },
                label = { Text("Port", color = Color.Gray) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                colors = fieldColors
            )

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = certPin,
                onValueChange = { certPin = it },
                label = { Text("Certificate PIN (SHA256 Hex)", color = Color.Gray) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                colors = fieldColors
            )

            Spacer(modifier = Modifier.height(16.dp))
            Divider(color = Color(0xFF2C2C2C))

            // --- Auth mode toggle ---
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(
                    checked = useKeycloak,
                    onCheckedChange = { checked ->
                        if (checked && !useKeycloak) {
                            // Switching to KC: save current preshared key
                            prefs.edit().putString("saved_preshared_key", authToken).apply()
                        } else if (!checked && useKeycloak) {
                            // Switching to manual: restore saved preshared key
                            authToken = prefs.getString("saved_preshared_key", "") ?: ""
                        }
                        useKeycloak = checked
                        prefs.edit().putBoolean("saved_use_keycloak", checked).apply()
                        errorMessage = ""
                    },
                    colors = CheckboxDefaults.colors(
                        checkedColor = Color(0xFF673AB7),
                        uncheckedColor = Color.Gray,
                        checkmarkColor = Color.White
                    )
                )
                Text("Keycloak Authentication", color = Color.White, fontSize = 14.sp)
            }

            if (useKeycloak) {
                // --- Keycloak fields ---
                OutlinedTextField(
                    value = kcUrl,
                    onValueChange = { kcUrl = it },
                    label = { Text("Keycloak Server URL", color = Color.Gray) },
                    placeholder = { Text("https://auth.example.com") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    colors = fieldColors
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = kcRealm,
                    onValueChange = { kcRealm = it },
                    label = { Text("Realm", color = Color.Gray) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    colors = fieldColors
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = kcClientId,
                    onValueChange = { kcClientId = it },
                    label = { Text("Client ID", color = Color.Gray) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    colors = fieldColors
                )

                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = {
                        if (kcUrl.isEmpty()) {
                            errorMessage = "Please enter a Keycloak Server URL."
                        } else {
                            prefs.edit()
                                .putString("saved_kc_url", kcUrl)
                                .putString("saved_kc_realm", kcRealm)
                                .putString("saved_kc_client_id", kcClientId)
                                .apply()
                            errorMessage = ""
                            OAuthHelper.startAuth(context, kcUrl, kcRealm, kcClientId)
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF673AB7)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Login with Keycloak")
                }

                // Show authentication status
                if (authToken.isNotEmpty()) {
                    Text(
                        text = "Authenticated",
                        color = Color(0xFF00FF7F),
                        fontSize = 12.sp,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            } else {
                // --- Preshared Key field (mandatory without Keycloak) ---
                OutlinedTextField(
                    value = authToken,
                    onValueChange = { authToken = it },
                    label = { Text("Preshared Key", color = Color.Gray) },
                    placeholder = { Text("Pre-shared token") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    colors = fieldColors
                )
            }

            // Error display
            if (errorMessage.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = errorMessage,
                    color = Color(0xFFFF3B30),
                    fontSize = 12.sp
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

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
        } // end scrollable content Column

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = {
                if (isConnected) {
                    onDisconnect()
                } else {
                    errorMessage = ""
                    if (serverIp.isEmpty()) {
                        errorMessage = "Please enter a server endpoint."
                    } else if (useKeycloak) {
                        if (kcUrl.isEmpty()) {
                            errorMessage = "Please enter Keycloak server details."
                        } else if (authToken.isEmpty()) {
                            errorMessage = "Please login with Keycloak first."
                        } else {
                            prefs.edit()
                                .putString("saved_kc_url", kcUrl)
                                .putString("saved_kc_realm", kcRealm)
                                .putString("saved_kc_client_id", kcClientId)
                                .apply()
                            onConnect(serverIp, serverPort, authToken, certPin)
                        }
                    } else {
                        if (authToken.isEmpty()) {
                            errorMessage = "Please enter a Preshared Key."
                        } else {
                            onConnect(serverIp, serverPort, authToken, certPin)
                        }
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

// --- Helper to convert any Drawable to Bitmap ---
fun drawableToBitmap(drawable: Drawable): Bitmap? {
    return try {
        if (drawable is BitmapDrawable) {
            return drawable.bitmap
        }
        val width = if (drawable.intrinsicWidth > 0) drawable.intrinsicWidth else 48
        val height = if (drawable.intrinsicHeight > 0) drawable.intrinsicHeight else 48
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        drawable.setBounds(0, 0, canvas.width, canvas.height)
        drawable.draw(canvas)
        bitmap
    } catch (e: Exception) {
        null
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
    initialMode: String, // "include" or "exclude"
    initialSelection: String, // comma separated packages
    initialTransportMode: Int, // 0=QUIC, 1=HTTP/3, 2=HTTP/2
    onBack: (String, String, Int) -> Unit
) {
    val context = LocalContext.current
    var mode by remember { mutableStateOf<String>(initialMode) } // "include", "exclude"
    var transportMode by remember { mutableStateOf<Int>(initialTransportMode) }
    
    val selectedPackages = remember { 
        mutableStateListOf<String>().apply { 
            addAll(initialSelection.split(",").map { it.trim() }.filter { it.isNotEmpty() })
        } 
    }
    
    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var isLoading by remember { mutableStateOf<Boolean>(true) }

    LaunchedEffect(Unit) {
        // Load apps in background
        val appList = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
             // Basic fetch
             val pm = context.packageManager
             val packages = pm.getInstalledPackages(0)
             packages.mapNotNull { pkg ->
                 val appInfo = pkg.applicationInfo ?: return@mapNotNull null
                 // Filter out system apps loosely (optimized for user apps)
                 val isSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                 // We show updated system apps too
                 val isUpdatedSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                 
                 // Show only if it has a launcher intent (user runnable)
                 val launchIntent = pm.getLaunchIntentForPackage(pkg.packageName)
                 
                 if (launchIntent != null && (!isSystem || isUpdatedSystem)) {
                     val iconDrawable = appInfo.loadIcon(pm)
                     val imageBitmap = drawableToBitmap(iconDrawable)?.asImageBitmap()
                     
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
        // Header
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 16.dp)
        ) {
            IconButton(onClick = { onBack(mode, selectedPackages.joinToString(","), transportMode) }) {
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
                    text = "Transport Mode",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp
                )
                val transportLabels = listOf("QUIC (Standard)", "HTTP/3 (Anti-Censorship)", "HTTP/2 (Anti-Censorship/TCP)")
                transportLabels.forEachIndexed { index, label ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { transportMode = index }
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = transportMode == index,
                            onClick = { transportMode = index },
                            colors = RadioButtonDefaults.colors(
                                selectedColor = Color(0xFF007AFF),
                                unselectedColor = Color.Gray
                            )
                        )
                        Text(
                            text = label,
                            color = if (transportMode == index) Color.White else Color.Gray,
                            fontSize = 14.sp,
                            modifier = Modifier.padding(start = 4.dp)
                        )
                    }
                }
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))

        // --- Battery Optimization Request ---
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
                Text(
                    text = "Battery Optimization",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp
                )
                Text(
                    text = "Ensure the VPN is not killed in the background.",
                    color = Color.Gray,
                    fontSize = 12.sp
                )
            }
            Icon(Icons.Default.Lock, contentDescription = null, tint = Color.Gray, modifier = Modifier.size(24.dp))
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
            onClick = { onBack(mode, selectedPackages.joinToString(","), transportMode) },
            modifier = Modifier.fillMaxWidth().height(50.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Save & Back", fontSize = 16.sp)
        }
    }
}
