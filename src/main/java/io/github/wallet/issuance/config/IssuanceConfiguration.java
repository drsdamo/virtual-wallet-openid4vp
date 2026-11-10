package io.github.wallet.issuance.config;

import io.github.wallet.credentials.service.CredentialStore;
import io.github.wallet.credentials.support.ReceivedCredentialReader;
import io.github.wallet.issuance.service.IssuanceService;
import io.github.wallet.issuance.service.PendingOfferRegistry;
import io.github.wallet.issuance.service.dao.ReceivedCredentialDao;
import io.github.wallet.issuance.support.OpenId4VciClient;
import io.github.wallet.issuance.support.ProofJwtFactory;
import io.github.wallet.presentation.support.openid4vp.ExchangeLog;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.json.JsonMapper;

/** Beans du domaine issuance : client OpenID4VCI, stockage des credentials reçus et file des offres en attente. */
@Configuration(proxyBeanMethods = false)
class IssuanceConfiguration {

    /** Client HTTP des émetteurs, avec son propre journal d'échanges ; fermé avec le contexte. */
    @Bean(destroyMethod = "close")
    OpenId4VciClient openId4VciClient(JsonMapper json) {
        return new OpenId4VciClient(json, new ExchangeLog(500));
    }

    @Bean
    ReceivedCredentialDao receivedCredentialDao(JdbcTemplate jdbc) {
        return new ReceivedCredentialDao(jdbc);
    }

    @Bean
    IssuanceService issuanceService(OpenId4VciClient client, ReceivedCredentialDao dao, CredentialStore store) {
        return new IssuanceService(client, dao, store, new ProofJwtFactory(Clock.systemUTC()),
                new ReceivedCredentialReader(), Clock.systemUTC());
    }

    /** Offres reçues en attente de la décision du porteur. */
    @Bean
    PendingOfferRegistry pendingOfferRegistry() {
        return new PendingOfferRegistry(Clock.systemUTC());
    }
}
