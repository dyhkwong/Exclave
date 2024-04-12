plugins {
    id("com.android.application")
}

android {
    defaultConfig {
        applicationId = "com.github.dyhkwong.sagernet.plugin.brook"
    }
    namespace = "io.nekohasekai.sagernet.plugin.brook"
}

setupPlugin("brook")