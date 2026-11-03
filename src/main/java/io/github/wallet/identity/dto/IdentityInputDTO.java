package io.github.wallet.identity.dto;

import java.time.LocalDate;
import java.util.List;

/** Corps de création et de modification d'une identité. Les claims ne sont lus qu'à la création. */
public record IdentityInputDTO(String familyName, String givenName, LocalDate birthDate, List<ClaimInputDTO> claims) {
}
