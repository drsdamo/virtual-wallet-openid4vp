package io.github.wallet.identity.dto;

import io.github.wallet.identity.support.ClaimScope;
import io.github.wallet.identity.support.ClaimType;

/** Claim additionnel rattaché à une identité, en plus du nom, du prénom et de la date de naissance. */
public record IdentityClaimDTO(String id, String name, ClaimType type, String value, ClaimScope scope) {
}
