// Top-level build file where you can add configuration options common to all sub-projects/modules.
allprojects {
    apply(from = "${rootProject.projectDir}/repositories.gradle.kts")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}

plugins {
    id("com.google.devtools.ksp") version "2.3.4" apply false
    id("com.mikepenz.aboutlibraries.plugin") version "14.0.0-b01" apply false
}
