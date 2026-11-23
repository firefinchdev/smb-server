plugins {
    id("com.android.application")
}

android {
    namespace = "dev.smbserver"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.smbserver"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}
