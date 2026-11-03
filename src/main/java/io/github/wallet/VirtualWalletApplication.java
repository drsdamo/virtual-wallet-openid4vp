package io.github.wallet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Point d'entrée du wallet de test OpenID4VP.
 * <p>
 * {@code @ConfigurationPropertiesScan} enregistre {@link io.github.wallet.config.WalletProperties} ;
 * les beans sont déclarés dans les classes {@code *Configuration} de chaque domaine.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class VirtualWalletApplication {

    public static void main(String[] args) {
        SpringApplication.run(VirtualWalletApplication.class, args);
    }
}
