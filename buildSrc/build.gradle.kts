plugins {
    `java-gradle-plugin`
    `kotlin-dsl`
}

apply(from = "../repositories.gradle.kts")

dependencies {
    implementation("com.android.tools.build:gradle:8.13.1")
    implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.21")
    implementation("org.kohsuke:github-api:1.330")
    implementation("com.squareup.okhttp3:okhttp:5.3.2")
    implementation("com.google.protobuf:protobuf-gradle-plugin:0.9.5")
}