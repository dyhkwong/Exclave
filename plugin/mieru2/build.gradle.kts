plugins {
    id("com.android.application")
}

android {
    defaultConfig {
        applicationId = "com.github.dyhkwong.sagernet.plugin.mieru2"
    }
    namespace = "io.nekohasekai.sagernet.plugin.mieru2"
}

setupPlugin("mieru2")