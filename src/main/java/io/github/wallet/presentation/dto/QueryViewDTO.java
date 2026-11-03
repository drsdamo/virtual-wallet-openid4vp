package io.github.wallet.presentation.dto;

import java.util.List;

/** Résultat d'une requête DCQL : le credential retenu et les claims divulgués, ou la raison de l'échec. */
public record QueryViewDTO(String queryId, String format, List<String> requestedTypes, String credentialId,
                           List<List<Object>> disclosedClaims, String reason) {
}
