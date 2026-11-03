package io.github.wallet.identity.dto;

import java.util.List;

/** Identité et credentials émis pour elle : réponse de l'API identités. */
public record IdentityViewDTO(IdentityDTO identity, List<CredentialRefDTO> credentials) {
}
