package io.github.wallet.identity.dto;

/** Référence d'un credential émis pour une identité (sans ses claims). */
public record CredentialRefDTO(String id, String format, String type) {
}
