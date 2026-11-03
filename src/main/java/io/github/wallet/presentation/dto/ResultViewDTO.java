package io.github.wallet.presentation.dto;

import io.github.wallet.presentation.support.Fault;

import java.net.URI;
import java.util.List;
import java.util.Set;

/** Réponse du verifier à accept, decline ou report-error, avec les échanges HTTP de la présentation. */
public record ResultViewDTO(String id, boolean accepted, URI redirectUri, Set<Fault> faults,
                            List<HttpExchangeDTO> exchanges) {
}
