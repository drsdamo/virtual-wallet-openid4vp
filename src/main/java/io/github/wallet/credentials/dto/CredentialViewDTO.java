package io.github.wallet.credentials.dto;

import java.util.Map;

/** Credential détenu par le wallet, avec ses claims en clair (affichage uniquement). */
public record CredentialViewDTO(String id, String format, String type, Map<String, Object> claims) {
}
