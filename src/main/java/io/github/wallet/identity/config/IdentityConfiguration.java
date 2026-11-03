package io.github.wallet.identity.config;

import io.github.wallet.credentials.service.CredentialStore;
import io.github.wallet.credentials.support.TestPersona;
import io.github.wallet.identity.service.IdentityService;
import io.github.wallet.identity.service.dao.IdentityDao;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

/** Beans du domaine identity : DAO et service. */
@Configuration(proxyBeanMethods = false)
class IdentityConfiguration {

    /** DAO sur le {@code JdbcTemplate} auto-configuré par Spring Boot à partir de la {@code DataSource}. */
    @Bean
    IdentityDao identityDao(JdbcTemplate jdbc) {
        return new IdentityDao(jdbc);
    }

    /**
     * {@code @Transactional} et {@code @EventListener} fonctionnent sur un {@code @Bean} comme sur un {@code @Service} :
     * Spring crée le proxy transactionnel quelle que soit la façon dont le bean est déclaré.
     */
    @Bean
    IdentityService identityService(IdentityDao dao, CredentialStore store, TestPersona persona) {
        return new IdentityService(dao, store, persona);
    }
}
