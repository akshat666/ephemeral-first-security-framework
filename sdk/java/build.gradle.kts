plugins {
    java
    `java-library`
    signing
    id("com.vanniktech.maven.publish") version "0.30.0"
}

group = "app.hideit"
version = "0.1.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

repositories {
    mavenCentral()
}

val jacksonVersion = "2.16.1"
val jedisVersion = "5.1.0"
val bouncycastleVersion = "1.77"
val junitVersion = "5.10.1"
val testcontainersVersion = "1.19.3"

dependencies {
    // JSON Serialization
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:$jacksonVersion")

    // Redis Client (optional)
    compileOnly("redis.clients:jedis:$jedisVersion")

    // Cryptography (Ed25519, additional algorithms)
    implementation("org.bouncycastle:bcprov-jdk18on:$bouncycastleVersion")

    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("org.testcontainers:testcontainers:$testcontainersVersion")
    testImplementation("org.testcontainers:junit-jupiter:$testcontainersVersion")

    // Jedis needed for tests
    testImplementation("redis.clients:jedis:$jedisVersion")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showExceptions = true
        showCauses = true
        showStackTraces = true
    }
}

tasks.compileJava {
    options.encoding = "UTF-8"
}

tasks.compileTestJava {
    options.encoding = "UTF-8"
}

mavenPublishing {
    publishToMavenCentral(com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL, automaticRelease = true)
    signAllPublications()

    pom {
        name.set("EFSF Java SDK")
        description.set("Ephemeral-First Security Framework - Java SDK")
        url.set("https://github.com/efsf/efsf")

        licenses {
            license {
                name.set("Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0")
            }
        }

        developers {
            developer {
                name.set("EFSF Contributors")
                url.set("https://github.com/efsf/efsf")
            }
        }

        scm {
            connection.set("scm:git:git://github.com/efsf/efsf.git")
            developerConnection.set("scm:git:ssh://github.com/efsf/efsf.git")
            url.set("https://github.com/efsf/efsf")
        }
    }
}

signing {
    useGpgCmd()
    isRequired = System.getenv("GPG_PASSPHRASE") != null
}
