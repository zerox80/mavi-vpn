plugins {
    id("com.android.application")
    id("org.mozilla.rust-android-gradle.rust-android")
}

android {
    namespace = "com.mavi.vpn"
    compileSdk = 34
    ndkVersion = "28.1.13356709"

    defaultConfig {
        applicationId = "com.mavi.vpn"
        minSdk = 26 // Android 8.0 (Oreo) for better VpnService support
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.4"
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

cargo {
    module = "src/main/rust"
    libname = "mavivpn"
    targets = listOf("arm", "arm64", "x86", "x86_64")
    apiLevel = 26
    profile = "release" // Force release for speed
}

tasks.register("copyNativeLibs") {
    dependsOn("cargoBuild")
    val targetDir = file("../../target")
    val jniLibDir = file("src/main/jniLibs")

    doLast {
        if (!jniLibDir.exists()) {
            jniLibDir.mkdirs()
        }
        
        // Copy arm64
        copy {
            from(File(targetDir, "aarch64-linux-android/release/libmavivpn.so"))
            into(File(jniLibDir, "arm64-v8a"))
        }

        // Copy arm
        copy {
            from(File(targetDir, "armv7-linux-androideabi/release/libmavivpn.so"))
            into(File(jniLibDir, "armeabi-v7a"))
        }
        
        // Copy x86
        copy {
            from(File(targetDir, "i686-linux-android/release/libmavivpn.so"))
            into(File(jniLibDir, "x86"))
        }
        
        // Copy x86_64
        copy {
            from(File(targetDir, "x86_64-linux-android/release/libmavivpn.so"))
            into(File(jniLibDir, "x86_64"))
        }
    }
}

tasks.whenTaskAdded {
    if (this.name == "mergeDebugJniLibFolders" || this.name == "mergeReleaseJniLibFolders") {
        this.dependsOn("copyNativeLibs")
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")
    implementation("androidx.activity:activity-compose:1.12.4")
    implementation(platform("androidx.compose:compose-bom:2026.02.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
}
