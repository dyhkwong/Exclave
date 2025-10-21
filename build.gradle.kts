// Top-level build file where you can add configuration options common to all sub-projects/modules.
allprojects {
    apply(from = "${rootProject.projectDir}/repositories.gradle.kts")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}

plugins {
    id("com.google.devtools.ksp") version "2.2.20-2.0.4" apply false
}
