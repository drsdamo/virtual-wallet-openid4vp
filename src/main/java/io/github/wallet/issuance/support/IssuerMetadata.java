package io.github.wallet.issuance.support;

import java.util.List;
import java.util.Map;

/**
 * Metadata de l'émetteur ({@code /.well-known/openid-credential-issuer}, OpenID4VCI 1.0 §12.2).
 *
 * @param authorizationServers     serveurs d'autorisation déclarés ; vide = l'émetteur est son propre AS
 * @param nonceEndpoint            {@code null} si l'émetteur n'en publie pas (proof sans {@code nonce})
 * @param notificationEndpoint     {@code null} si absent
 * @param encryptionRequired       {@code credential_response_encryption.encryption_required} (non géré)
 * @param configurations           credentials émis, par identifiant de configuration
 * @param displayName              nom affichable de l'émetteur, s'il existe
 * @param url                      URL d'où les metadata ont été lues
 */
public record IssuerMetadata(String credentialIssuer, List<String> authorizationServers, String credentialEndpoint,
                             String nonceEndpoint, String notificationEndpoint, boolean encryptionRequired,
                             Map<String, CredentialConfiguration> configurations, String displayName, String url) {
}
