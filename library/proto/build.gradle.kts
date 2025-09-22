plugins {
    `java-library`
}

java {
    sourceSets.getByName("main").resources.srcDir(rootProject.file("library/proto/main"))
}
