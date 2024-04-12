plugins {
    id("com.android.application")
}

android {
    defaultConfig {
        applicationId = "io.nekohasekai.sagernet.plugin.shadowtls"
    }
    namespace = "io.nekohasekai.sagernet.plugin.shadowtls"
}

setupPlugin("shadowtls")