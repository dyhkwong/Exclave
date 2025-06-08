plugins {
    id("com.android.application")
}

android {
    defaultConfig {
        applicationId = "com.github.dyhkwong.sagernet.plugin.tuic5"
    }
    namespace = "io.nekohasekai.sagernet.plugin.tuic5"
}

setupPlugin("tuic5")