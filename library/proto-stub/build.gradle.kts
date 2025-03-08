import com.google.protobuf.gradle.*

plugins {
    id("com.android.library")
    kotlin("android")
    id("com.google.protobuf")
}

setupCommon()

dependencies {
    protobuf(project(":library:proto"))

    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.1")
    api("com.google.protobuf:protobuf-java:4.30.0")
}
android {
    namespace = "com.v2ray.core"
    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:4.30.0"
    }
    generateProtoTasks {
        all().forEach {
            it.plugins {
                create("java")
            }
        }
    }
}
