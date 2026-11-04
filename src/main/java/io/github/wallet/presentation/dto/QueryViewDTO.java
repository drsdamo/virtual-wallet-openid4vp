package io.github.wallet.presentation.dto;

import java.util.List;

/**
 * Résultat d'une requête DCQL : le credential retenu et les claims divulgués, ou la raison de l'échec.
 *
 * @param disclosedClaims chemins des claims divulgués ; {@code null} = credential entier
 * @param claims          mêmes claims avec leur valeur, pour informer le porteur avant qu'il accepte
 */
public record QueryViewDTO(String queryId, String format, List<String> requestedTypes, String credentialId,
                           List<List<Object>> disclosedClaims, List<ClaimViewDTO> claims, String reason) {
}
