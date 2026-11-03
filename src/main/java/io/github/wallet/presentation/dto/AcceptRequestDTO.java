package io.github.wallet.presentation.dto;

import io.github.wallet.presentation.support.Fault;

import java.util.Set;

/** Corps de {@code accept} : défauts à injecter dans la réponse (vide ou absent : réponse correcte). */
public record AcceptRequestDTO(Set<Fault> faults) {
}
