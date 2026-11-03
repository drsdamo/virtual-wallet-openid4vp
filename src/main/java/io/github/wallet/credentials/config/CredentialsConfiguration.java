package io.github.wallet.credentials.config;

import io.github.wallet.config.WalletProperties;
import io.github.wallet.credentials.service.CredentialStore;
import io.github.wallet.credentials.service.TestCredentialIssuer;
import io.github.wallet.credentials.support.TestPersona;
import io.github.wallet.credentials.support.WalletKeyMaterial;
import io.github.wallet.credentials.support.WalletKeyMaterialLoader;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Beans du domaine credentials : clés de l'autorité de test, émetteur et stock de credentials. */
@Configuration(proxyBeanMethods = false)
class CredentialsConfiguration {

    /** Clés et certificats persistés dans {@code wallet.data-dir}, créés au premier démarrage. */
    @Bean
    WalletKeyMaterial walletKeyMaterial(WalletProperties properties) {
        return new WalletKeyMaterialLoader().loadOrCreate(properties.dataDir());
    }

    /** Identité fictive créée quand la base est vide. */
    @Bean
    TestPersona testPersona() {
        return new TestPersona();
    }

    @Bean
    TestCredentialIssuer testCredentialIssuer(WalletKeyMaterial keys) {
        return new TestCredentialIssuer(keys);
    }

    @Bean
    CredentialStore credentialStore(TestCredentialIssuer issuer) {
        return new CredentialStore(issuer);
    }
}
