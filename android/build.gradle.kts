// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("com.android.application") version "9.0.1" apply false
    id("org.mozilla.rust-android-gradle.rust-android") version "0.9.6" apply false
}

buildscript {
    repositories {
        google()
        mavenCentral()
    }
}
