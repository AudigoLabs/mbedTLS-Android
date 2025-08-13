@file:Suppress("UnstableApiUsage")

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.vanniktech.publish)
}

group = "com.audigolabs.mbedtls"
version = "1.0.0"

android {
    compileSdk = 36
    namespace = "com.audigolabs.mbedtls.android"
    defaultConfig {
        compileSdk = 36
        ndkVersion = libs.versions.ndk.get()
        minSdk = libs.versions.sdkMin.get().toInt()

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

mavenPublishing {
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/AudigoLabs/mbedTLS-Android")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }
        }
    }
}

dependencies {
    implementation(fileTree("libs").matching { include("*.jar") })
    implementation(libs.android.annotations)
    testImplementation(libs.junit)
    androidTestImplementation(libs.android.test)
    androidTestImplementation(libs.android.espresso)
}
