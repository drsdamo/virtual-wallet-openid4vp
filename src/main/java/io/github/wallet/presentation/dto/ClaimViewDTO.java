package io.github.wallet.presentation.dto;

import java.util.List;

/**
 * Claim demandé par le verifier et la valeur que le wallet va divulguer.
 *
 * @param path  chemin DCQL (namespace puis élément pour un mdoc ; {@code null} = tous les éléments d'un tableau)
 * @param value valeur détenue par le wallet, {@code null} si absente
 */
public record ClaimViewDTO(List<Object> path, Object value) {
}
