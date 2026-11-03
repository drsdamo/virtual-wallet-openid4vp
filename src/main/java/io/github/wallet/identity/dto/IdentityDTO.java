package io.github.wallet.identity.dto;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

/** Personne dont le wallet détient les credentials. */
public record IdentityDTO(
        String id,
        String familyName,
        String givenName,
        LocalDate birthDate,
        List<IdentityClaimDTO> claims,
        Instant createdAt,
        Instant updatedAt) {

    /** Copie défensive : la liste des claims est immuable et jamais {@code null}. */
    public IdentityDTO {
        claims = claims == null ? List.of() : List.copyOf(claims);
    }
}
