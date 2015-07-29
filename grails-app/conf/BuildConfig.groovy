import grails.util.Environment

grails.servlet.version = "3.0" // Change depending on target container compliance (2.5 or 3.0)
grails.project.class.dir = "target/classes"
grails.project.test.class.dir = "target/test-classes"
grails.project.test.reports.dir = "target/test-reports"
grails.project.target.level = 1.7
grails.project.source.level = 1.7
//grails.project.war.file = "target/${appName}-${appVersion}.war"

// If forking is disabled in the dev env, a NoSuchMethodError occurs during Spring initialization which prevents the app
// from starting. This problem only occurs when the app is launched from IntelliJ.
// Disabling forking in the test env allows us to access the application context from functional tests
if (Environment.developmentMode) {

    // jvmArgs allows us to connect a remote debugger in forked mode without having to use the `--debug-fork` flag
    // In other words, when run-app is executed in the dev env the app is always in debug mode
    // http://naleid.com/blog/2014/11/10/debugging-grails-forked-mode
    boolean waitForDebugger = false

    // the String contained in jvmArgs must not be a GString
    def jvmArgs = ["-Xrunjdwp:transport=dt_socket,server=y,suspend=${waitForDebugger ? 'y' : 'n'},address=5005".toString()]

    grails.project.fork = [
            // configure settings for compilation JVM, note that if you alter the Groovy version forked compilation is required
            //  compile: [maxMemory: 256, minMemory: 64, debug: false, maxPerm: 256, daemon:true],

            // configure settings for the test-app JVM, uses the daemon by default
            test   : [maxMemory: 1200, minMemory: 256, debug: false, maxPerm: 256, daemon: true, jvmArgs: jvmArgs],
            // configure settings for the run-app JVM
            run    : [maxMemory: 1200, minMemory: 256, debug: false, maxPerm: 256, forkReserve: false, jvmArgs: jvmArgs],
            // configure settings for the run-war JVM
            war    : [maxMemory: 1200, minMemory: 256, debug: false, maxPerm: 256, forkReserve: false, jvmArgs: jvmArgs],
            // configure settings for the Console UI JVM
            console: [maxMemory: 1200, minMemory: 256, debug: false, maxPerm: 256, jvmArgs: jvmArgs]
    ]
}


grails.project.dependency.resolver = "maven" // or ivy
grails.project.dependency.resolution = {
    // inherit Grails' default dependencies
    inherits("global") {
        // specify dependency exclusions here; for example, uncomment this to disable ehcache:
        // excludes 'ehcache'
    }
    log "error" // log level of Ivy resolver, either 'error', 'warn', 'info', 'debug' or 'verbose'
    checksums true // Whether to verify checksums on resolve
    legacyResolve false // whether to do a secondary resolve on plugin installation, not advised and here for backwards compatibility

    repositories {
        grailsPlugins()
        grailsHome()
        mavenLocal()
        grailsCentral()
        mavenCentral()
        mavenRepo "http://repository.springsource.com/maven/bundles/external"
        mavenRepo "http://repo.grails.org/grails/core"

        // required by the browser-detection plugin if version > 0.4.3
        mavenRepo 'https://raw.githubusercontent.com/HaraldWalker/user-agent-utils/mvn-repo/'
    }

    dependencies {
        // specify dependencies here under either 'build', 'compile', 'runtime', 'test' or 'provided' scopes eg.

        runtime 'mysql:mysql-connector-java:5.1.34'

        compile 'org.jsoup:jsoup:1.8.1',
                'org.imgscalr:imgscalr-lib:4.2',
                'javax.media.jai:com.springsource.javax.media.jai.core:1.1.3',
                'org.codehaus.groovy.modules.http-builder:http-builder:0.7.1',
                'com.neovisionaries:nv-i18n:1.13',
                'org.pac4j:pac4j-core:1.6.0',
                'org.pac4j:pac4j-oauth:1.6.0'

        test    'org.gmock:gmock:0.8.3',
                'org.hamcrest:hamcrest-all:1.3'
    }

    plugins {
        build   ':tomcat:7.0.55.3'
        runtime ':hibernate:3.6.10.19'

        compile ":airbrake:0.9.4",
                ":asset-pipeline:2.1.5",
                ":audit-logging:1.0.4",
                ":browser-detection:2.2.0",
                ":cache:1.1.8",
                ":commentable:0.8.1",
                ":export:1.6",
                ":fields:1.4",
                ":geocode:0.3",
                ":less-asset-pipeline:2.1.0",
                ":searchable:0.6.9",
                ":simple-captcha:1.0.0",
                ":spring-security-core:1.2.7.4",
                ":taggable:1.1.0",
                ":webxml:1.4.1"

        runtime ":cache-ehcache:1.0.5",
                ":cache-headers:1.1.7",
                ":console:1.5.4",
                ":feeds:1.6",
                ":flash-helper:0.9.9",
                ":jdbc-pool:7.0.47",
                ":jquery:1.11.1",
                ":mail:1.0.7",
                ":quartz:1.0.2",
                ":simple-blog:0.3.5"

        test    ":build-test-data:2.4.0"
    }
}

//grails.plugin.location.'simple-blog' = "../grails-simple-blog"
