package io.github.wallet.config;

import java.nio.file.Path;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Paramètres du wallet, lus sous {@code wallet.*}.
 *
 * @param trustAllVerifiers    accepte n'importe quelle chaîne de certificats pour les clients x509_san_dns / x509_hash.
 *                             Réservé aux tests : ne jamais l'activer hors d'un environnement de test.
 * @param dataDir              répertoire des clés de l'autorité de test et du wallet (PEM) et de la base SQLite.
 * @param verifierTrustAnchors fichiers PEM des certificats racines (ou auto-signés) des verifiers de confiance.
 */
@ConfigurationProperties("wallet")
public record WalletProperties(
        @DefaultValue("false") boolean trustAllVerifiers,
        @DefaultValue("./wallet-data") Path dataDir,
        @DefaultValue List<Path> verifierTrustAnchors) {
}
