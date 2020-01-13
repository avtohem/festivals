import ie.festivals.hibernate.UTF8MySQL5InnoDBDialect
import java.sql.Connection

dataSource {
    pooled = true
    driverClassName = "com.mysql.cj.jdbc.Driver"
    dialect = UTF8MySQL5InnoDBDialect.name
    logSql = false
    url = "jdbc:mysql://localhost/festival?useUnicode=yes"

    properties {
        jmxEnabled = true
        initialSize = 5
        maxActive = 50
        minIdle = 5
        maxIdle = 25
        maxWait = 10000
        maxAge = 10 * 60000
        timeBetweenEvictionRunsMillis = 5000
        minEvictableIdleTimeMillis = 60000
        validationQuery = "SELECT 1"
        validationQueryTimeout = 3
        validationInterval = 15000
        testOnBorrow = true
        testWhileIdle = true
        testOnReturn = false
        jdbcInterceptors = "ConnectionState"
        defaultTransactionIsolation = Connection.TRANSACTION_READ_COMMITTED
    }
}

hibernate {
    cache.use_second_level_cache = true
    cache.use_query_cache = true
    cache.region.factory_class = 'org.hibernate.cache.SingletonEhCacheRegionFactory' // Hibernate 3
    singleSession = true // configure OSIV singleSession mode
    flush.mode = 'manual' // OSIV session flush mode outside of transactional context
    format_sql = true
}

environments {

    development {
        dataSource {
            dbCreate = "create"
            //logSql = true
        }
    }

    test {
        dataSource {
            dbCreate = "create"
            username = "root"
            password = ""
            url = "jdbc:mysql://localhost/festival_test?useUnicode=yes&characterEncoding=UTF-8"
        }
    }

    production {
        dataSource {
            dbCreate = "update"
            url = "jdbc:mysql://localhost/festival?useUnicode=yes&characterEncoding=UTF-8"
        }
    }
}
