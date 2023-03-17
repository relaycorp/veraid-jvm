rootProject.name = "veraid"

pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
    }
}
plugins {
    id("com.gradle.enterprise").version("3.12.4")
}
gradleEnterprise {
    buildScan {
        termsOfServiceUrl = "https://gradle.com/terms-of-service"
        termsOfServiceAgree = "yes"
        publishOnFailureIf(!System.getenv("CI").isNullOrEmpty())
    }
}
