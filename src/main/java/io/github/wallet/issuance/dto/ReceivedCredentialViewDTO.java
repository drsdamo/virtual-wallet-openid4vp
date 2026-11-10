package io.github.wallet.issuance.dto;

import java.time.Instant;
import java.util.List;

/** Credential reçu, exposé par l'API (sans la clé privée). */
public record ReceivedCredentialViewDTO(String id, String identityId, String credentialIssuer, String configurationId,
                                        String format, String type, List<String> warnings, Instant receivedAt) {
}
