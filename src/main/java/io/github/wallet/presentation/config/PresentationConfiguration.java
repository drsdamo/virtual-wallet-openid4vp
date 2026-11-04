package io.github.wallet.presentation.config;

import io.github.wallet.config.WalletProperties;
import io.github.wallet.credentials.service.CredentialStore;
import io.github.wallet.credentials.support.WalletKeyMaterial;
import io.github.wallet.presentation.service.PendingPresentationRegistry;
import io.github.wallet.presentation.service.PresentationService;
import io.github.wallet.presentation.support.ClaimValueReader;
import io.github.wallet.presentation.support.openid4vp.OpenId4VpWalletClient;
import io.github.wallet.presentation.support.openid4vp.TrustAnchorLoader;
import io.github.wallet.presentation.support.openid4vp.VerifierTrust;
import io.github.wallet.presentation.support.openid4vp.WalletConfigFactory;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Beans du domaine presentation : client OpenID4VP, service de présentation et file des demandes en attente. */
@Configuration(proxyBeanMethods = false)
class PresentationConfiguration {

    /** Client OpenID4VP, avec la politique de confiance configurée ; fermé avec le contexte (client HTTP). */
    @Bean(destroyMethod = "close")
    OpenId4VpWalletClient openId4VpWalletClient(WalletProperties properties) {
        var trust = new VerifierTrust(
                new TrustAnchorLoader().load(properties.verifierTrustAnchors()), properties.trustAllVerifiers());
        return new OpenId4VpWalletClient(new WalletConfigFactory().create(trust));
    }

    @Bean
    PresentationService presentationService(OpenId4VpWalletClient client, CredentialStore store, WalletKeyMaterial keys) {
        return new PresentationService(client, store, keys);
    }

    /** Présentations reçues en attente de la décision du porteur. */
    @Bean
    PendingPresentationRegistry pendingPresentationRegistry() {
        return new PendingPresentationRegistry(Clock.systemUTC());
    }

    @Bean
    ClaimValueReader claimValueReader() {
        return new ClaimValueReader();
    }
}
