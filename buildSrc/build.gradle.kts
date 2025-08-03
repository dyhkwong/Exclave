plugins {
    `java-gradle-plugin`
    `kotlin-dsl`
}

apply(from = "../repositories.gradle.kts")

dependencies {
    implementation("com.android.tools.build:gradle:8.12.0")
    implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.0")
    implementation("cn.hutool:hutool-http:5.8.39")
    implementation("cn.hutool:hutool-crypto:5.8.39")
    implementation("org.kohsuke:github-api:1.329")
    implementation("com.squareup.okhttp3:okhttp:5.1.0")
    implementation("com.google.protobuf:protobuf-gradle-plugin:0.9.5")
}