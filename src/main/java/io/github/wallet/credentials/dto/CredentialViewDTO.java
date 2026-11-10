package io.github.wallet.credentials.dto;

import java.util.Map;

/**
 * Credential détenu par le wallet, avec ses claims en clair (affichage uniquement).
 *
 * @param issuer autorité de test, ou {@code credential_issuer} d'un credential reçu par OpenID4VCI
 */
public record CredentialViewDTO(String id, String format, String type, String issuer, Map<String, Object> claims) {
}
