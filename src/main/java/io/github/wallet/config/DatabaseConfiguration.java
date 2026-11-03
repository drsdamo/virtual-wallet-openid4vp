package io.github.wallet.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.sql.DataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Base SQLite du wallet ; le schéma est créé au démarrage par {@code schema.sql}. */
@Configuration(proxyBeanMethods = false)
class DatabaseConfiguration {

    private static final Logger log = LogManager.getLogger(DatabaseConfiguration.class);

    /**
     * Base {@code wallet.db} dans le répertoire de données. Une seule connexion : SQLite sérialise de toute façon
     * les écritures, et une connexion unique évite les erreurs {@code SQLITE_BUSY}.
     * <p>
     * {@code foreign_keys=on} active le {@code ON DELETE CASCADE} des claims ; {@code journal_mode=WAL} permet
     * des lectures pendant une écriture.
     */
    @Bean
    DataSource dataSource(WalletProperties properties) {
        Path dir = properties.dataDir().toAbsolutePath();
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        Path db = dir.resolve("wallet.db");
        log.info("SQLite database {}", db);
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:sqlite:" + db + "?foreign_keys=on&journal_mode=WAL");
        config.setMaximumPoolSize(1);
        config.setPoolName("wallet-sqlite");
        return new HikariDataSource(config);
    }
}
