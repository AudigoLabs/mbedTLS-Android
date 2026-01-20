@file:Suppress("UnstableApiUsage")

import com.android.build.gradle.internal.cxx.configure.gradleLocalProperties

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.vanniktech.publish)
}

group = "com.audigolabs.mbedtls"
version = "1.0.7"

android {
    compileSdk = 36
    namespace = "com.audigolabs.mbedtls.android"
    defaultConfig {
        compileSdk = 36
        ndkVersion = libs.versions.ndk.get()
        minSdk = libs.versions.sdkMin.get().toInt()
        consumerProguardFiles("proguard-rules.pro")

        externalNativeBuild {
            cmake {
                cppFlags += ""
                arguments += listOf(
                    "-DANDROID_STL=c++_shared",
                    "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"
                )
            }
        }
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    externalNativeBuild {
        cmake {
            path("src/main/cpp/CMakeLists.txt")
        }
    }
}

publishing {
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/AudigoLabs/mbedTLS-Android")
            credentials {
                username = (project.findProperty("gpr.user") as String?)?.takeUnless { it.isBlank() }
                    ?: System.getenv("USERNAME")
                            ?: gradleLocalProperties(rootDir, providers).getProperty("github_username")
                password = (project.findProperty("gpr.key") as String?)?.takeUnless { it.isBlank() }
                    ?: System.getenv("TOKEN")
                            ?: gradleLocalProperties(rootDir, providers).getProperty("github_token")
            }
        }
    }
}

dependencies {
    implementation(fileTree("libs").matching { include("*.jar") })
    implementation(libs.android.annotations)
    implementation(libs.timber)
    testImplementation(libs.junit)
    androidTestImplementation(libs.android.test)
    androidTestImplementation(libs.android.espresso)
}
