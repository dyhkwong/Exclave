/******************************************************************************
 *                                                                            *
 * Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>             *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                       *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                            *
 ******************************************************************************/

import cn.hutool.core.codec.Base64
import com.android.build.api.dsl.*
import com.android.build.gradle.AbstractAppExtension
import com.android.build.gradle.internal.api.ApkVariantOutputImpl
import com.android.build.gradle.internal.api.BaseVariantOutputImpl
import org.apache.tools.ant.filters.StringInputStream
import org.gradle.api.JavaVersion
import org.gradle.api.Project
import org.gradle.kotlin.dsl.*
import java.util.*

private val Project.android
    get() = extensions.getByName<CommonExtension<BuildFeatures, BuildType, DefaultConfig, ProductFlavor, AndroidResources, Installation>>(
        "android"
    )
private val Project.androidApp get() = android as ApplicationExtension

private lateinit var metadata: Properties
private lateinit var localProperties: Properties

fun Project.requireMetadata(): Properties {
    if (!::metadata.isInitialized) {
        metadata = Properties().apply {
            load(rootProject.file("version.properties").inputStream())
        }
    }
    return metadata
}

fun Project.requireLocalProperties(): Properties {
    if (!::localProperties.isInitialized) {
        localProperties = Properties()

        val base64 = System.getenv("LOCAL_PROPERTIES")
        if (!base64.isNullOrBlank()) {

            localProperties.load(StringInputStream(Base64.decodeStr(base64)))
        } else if (project.rootProject.file("local.properties").exists()) {
            localProperties.load(rootProject.file("local.properties").inputStream())
        }
    }
    return localProperties
}

fun Project.setupCommon() {
    setupCommon("")
}

fun Project.setupCommon(projectName: String) {
    android.apply {
        buildToolsVersion = "36.0.0"
        compileSdk = 36
        defaultConfig {
            minSdk = if (projectName.lowercase(Locale.ROOT) == "naive") 24 else 21
        }
        buildTypes {
            getByName("release") {
                isMinifyEnabled = true
                @Suppress("UnstableApiUsage")
                vcsInfo.include = false
            }
        }
        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_21
            targetCompatibility = JavaVersion.VERSION_21
        }
        lint {
            showAll = true
            checkAllWarnings = true
            checkReleaseBuilds = false
            warningsAsErrors = true
            textOutput = project.file("build/lint.txt")
            htmlOutput = project.file("build/lint.html")
        }
        packaging {
            resources {
                excludes.addAll(
                    listOf(
                        "**/*.kotlin_*",
                        "/META-INF/*.version",
                        "/META-INF/native/**",
                        "/META-INF/native-image/**",
                        "/META-INF/INDEX.LIST",
                        "DebugProbesKt.bin",
                        "com/**",
                        "org/**",
                        "**/*.java",
                        "**/*.proto",
                    )
                )
            }
        }
        packaging {
            jniLibs.useLegacyPackaging = true
        }
        (this as? AbstractAppExtension)?.apply {
            buildTypes {
                getByName("release") {
                    isShrinkResources = true
                }
            }
            applicationVariants.forEach { variant ->
                variant.outputs.forEach {
                    it as BaseVariantOutputImpl
                    it.outputFileName = it.outputFileName.replace(
                        "app", "${project.name}-" + variant.versionName
                    ).replace("-release", "").replace("-oss", "")
                }
            }
        }
    }
    (android as? ApplicationExtension)?.apply {
        defaultConfig {
            targetSdk = 36
        }
    }
}

fun Project.setupAppCommon() {
    setupAppCommon("")
}

fun Project.setupAppCommon(projectName: String) {
    setupCommon(projectName)

    val lp = requireLocalProperties()
    val keystorePwd = lp.getProperty("KEYSTORE_PASS") ?: System.getenv("KEYSTORE_PASS")
    val alias = lp.getProperty("ALIAS_NAME") ?: System.getenv("ALIAS_NAME")
    val pwd = lp.getProperty("ALIAS_PASS") ?: System.getenv("ALIAS_PASS")

    androidApp.apply {
        if (keystorePwd != null) {
            signingConfigs {
                create("release") {
                    storeFile = rootProject.file("release.keystore")
                    storePassword = keystorePwd
                    keyAlias = alias
                    keyPassword = pwd
                    enableV3Signing = true
                }
            }
        }
        dependenciesInfo {
            includeInApk = false
            includeInBundle = false
        }
        buildTypes {
            val key = signingConfigs.findByName("release")
            if (key != null) {
                getByName("release").signingConfig = key
            }
        }
    }
}

fun Project.setupPlugin(projectName: String) {
    val propPrefix = projectName.uppercase(Locale.ROOT)
    val verName = requireMetadata().getProperty("${propPrefix}_VERSION_NAME").trim()
    val verCode = requireMetadata().getProperty("${propPrefix}_VERSION").trim().toInt()
    androidApp.defaultConfig {
        versionName = verName
        versionCode = verCode
    }

    apply(plugin = "kotlin-android")

    setupAppCommon(projectName)

    androidApp.apply {
        dependenciesInfo {
            includeInApk = false
            includeInBundle = false
        }

        this as AbstractAppExtension

        if (gradle.startParameter.taskNames.isNotEmpty() && gradle.startParameter.taskNames.any { it.lowercase().contains("assemble") }) {
            splits.abi {
                isEnable = true
                isUniversalApk = false

                reset()
                include("x86", "x86_64", "armeabi-v7a", "arm64-v8a")
            }
        }

        flavorDimensions.add("vendor")
        productFlavors {
            create("oss")
        }

        applicationVariants.all {
            outputs.all {
                this as BaseVariantOutputImpl
                outputFileName = outputFileName.replace(
                    project.name, "${project.name}-plugin-$versionName"
                ).replace("-release", "").replace("-oss", "")

            }
        }
    }

    dependencies.add("implementation", project(":plugin:api"))

}

fun Project.setupApp() {
    val pkgName = requireMetadata().getProperty("PACKAGE_NAME").trim()
    val verName = requireMetadata().getProperty("VERSION_NAME").trim()
    val verCode = requireMetadata().getProperty("VERSION_CODE").trim().toInt() * 5
    androidApp.apply {
        defaultConfig {
            applicationId = pkgName
            versionCode = verCode
            versionName = verName
        }
    }
    setupAppCommon()

    androidApp.apply {
        this as AbstractAppExtension

        buildTypes {
            getByName("release") {
                proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    file("proguard-rules.pro")
                )
            }
        }

        if (gradle.startParameter.taskNames.isNotEmpty() && gradle.startParameter.taskNames.any { it.lowercase().contains("assemble") }) {
            splits.abi {
                isEnable = true
                isUniversalApk = false
                reset()
                include("x86", "x86_64", "armeabi-v7a", "arm64-v8a")
            }
        }

        flavorDimensions.add("vendor")
        productFlavors {
            create("oss")
        }

        applicationVariants.all {
            outputs.forEach { output ->
                output as ApkVariantOutputImpl
                when (output.filters.find { it.filterType == "ABI" }?.identifier) {
                    "arm64-v8a" -> output.versionCodeOverride = verCode + 4
                    "x86_64" -> output.versionCodeOverride = verCode + 3
                    "armeabi-v7a" -> output.versionCodeOverride = verCode + 2
                    "x86" -> output.versionCodeOverride = verCode + 1
                }
            }
            outputs.all {
                this as BaseVariantOutputImpl
                outputFileName = outputFileName.replace(project.name, "Exclave-$versionName")
                    .replace("-release", "")
                    .replace("-oss", "")

            }
        }

        tasks.register("downloadAssets") {
            downloadAssets(update = false)
        }

        tasks.register("updateAssets") {
            downloadRootCAList()
            downloadAssets(update = true)
        }
    }

    dependencies {
        add("implementation", project(":plugin:api"))
    }
}