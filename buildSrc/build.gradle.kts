plugins {
    `java-gradle-plugin`
    `kotlin-dsl`
}

apply(from = "../repositories.gradle.kts")

dependencies {
    implementation("com.android.tools.build:gradle:8.9.2")
    implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:2.1.20")
    implementation("cn.hutool:hutool-http:5.8.37")
    implementation("cn.hutool:hutool-crypto:5.8.37")
    implementation("org.kohsuke:github-api:1.327")
    implementation("com.squareup.okhttp3:okhttp:5.0.0-alpha.14")
    implementation("com.google.protobuf:protobuf-gradle-plugin:0.9.5")
    implementation("com.github.ben-manes:gradle-versions-plugin:0.52.0")
}