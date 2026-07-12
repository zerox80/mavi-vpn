package com.mavi.vpn.ui.screens

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
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
import com.mavi.vpn.data.InstalledApp
import com.mavi.vpn.includeSplitTunnelSelectionIsValid
import com.mavi.vpn.ui.components.drawableToBitmap
import com.mavi.vpn.ui.components.toImageBitmap
import com.mavi.vpn.viewmodel.VpnViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun SplitTunnelingScreen(
    viewModel: VpnViewModel,
    onBack: () -> Unit,
    onSave: (String, String) -> Unit,
) {
    val context = LocalContext.current
    val initialMode by viewModel.splitMode.collectAsState()
    val initialSelection by viewModel.splitPackages.collectAsState()
    var mode by remember { mutableStateOf(initialMode) }
    val selectedPackages = remember {
        mutableStateListOf<String>().apply {
            addAll(initialSelection.split(",").map { it.trim() }.filter { it.isNotEmpty() })
        }
    }
    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        apps = loadLaunchableApps(context.packageManager)
        isLoading = false
    }

    fun save() {
        if (!includeSplitTunnelSelectionIsValid(mode, selectedPackages)) {
            Toast.makeText(context, "Select at least one app for include split tunneling.", Toast.LENGTH_SHORT).show()
            return
        }
        onSave(mode, selectedPackages.joinToString(","))
    }

    Column(
        modifier = Modifier.fillMaxSize().background(Color(0xFF121212)).padding(horizontal = 16.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = Color.White)
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(text = "Split Tunneling", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                Text(text = "Choose which apps use the VPN", color = Color.Gray, fontSize = 12.sp)
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth().background(Color(0xFF1E1E1E), RoundedCornerShape(8.dp)).padding(4.dp),
        ) {
            Button(
                onClick = { mode = "exclude" },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(6.dp),
                colors = ButtonDefaults.buttonColors(containerColor = if (mode == "exclude") Color(0xFF007AFF) else Color.Transparent),
            ) { Text("Exclude selected") }
            Button(
                onClick = { mode = "include" },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(6.dp),
                colors = ButtonDefaults.buttonColors(containerColor = if (mode == "include") Color(0xFF007AFF) else Color.Transparent),
            ) { Text("Include selected") }
        }

        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = if (mode == "include") "Only selected apps will use VPN." else "Selected apps will bypass VPN.",
            color = Color.Gray,
            fontSize = 14.sp,
        )
        Text(
            text = "${selectedPackages.size} selected",
            color = Color(0xFF007AFF),
            fontSize = 14.sp,
            modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
        )

        if (isLoading) {
            Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = Color(0xFF007AFF))
            }
        } else {
            LazyColumn(modifier = Modifier.weight(1f)) {
                items(apps, key = { it.packageName }) { app ->
                    val isSelected = selectedPackages.contains(app.packageName)
                    Row(
                        modifier = Modifier.fillMaxWidth().clickable {
                            if (isSelected) selectedPackages.remove(app.packageName)
                            else selectedPackages.add(app.packageName)
                        }.padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        if (app.icon != null) {
                            Image(bitmap = app.icon, contentDescription = null, modifier = Modifier.size(40.dp))
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
                                if (checked) selectedPackages.add(app.packageName)
                                else selectedPackages.remove(app.packageName)
                            },
                            colors = CheckboxDefaults.colors(
                                checkedColor = Color(0xFF007AFF),
                                uncheckedColor = Color.Gray,
                                checkmarkColor = Color.White,
                            ),
                        )
                    }
                    HorizontalDivider(color = Color(0xFF2C2C2C))
                }
            }
        }

        Button(
            onClick = ::save,
            modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp).height(50.dp),
            shape = RoundedCornerShape(12.dp),
        ) { Text("Save selection", fontSize = 16.sp) }
    }
}

private suspend fun loadLaunchableApps(packageManager: PackageManager): List<InstalledApp> =
    withContext(Dispatchers.IO) {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val launchableActivities = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryIntentActivities(launcherIntent, PackageManager.ResolveInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            packageManager.queryIntentActivities(launcherIntent, 0)
        }
        launchableActivities.mapNotNull { activity ->
            val activityInfo = activity.activityInfo ?: return@mapNotNull null
            val appInfo = activityInfo.applicationInfo ?: return@mapNotNull null
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            if (isSystem && !isUpdatedSystem) return@mapNotNull null

            InstalledApp(
                name = appInfo.loadLabel(packageManager).toString(),
                packageName = activityInfo.packageName,
                icon = drawableToBitmap(appInfo.loadIcon(packageManager))?.toImageBitmap(),
            )
        }.distinctBy { it.packageName }.sortedBy { it.name.lowercase() }
    }
