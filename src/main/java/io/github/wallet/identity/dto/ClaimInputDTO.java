package io.github.wallet.identity.dto;

import io.github.wallet.identity.support.ClaimScope;
import io.github.wallet.identity.support.ClaimType;

/**
 * Corps de création et de modification d'un claim.
 *
 * @param name  nom du claim ; un nom pointé ({@code address.locality}) crée un objet imbriqué (SD-JWT uniquement)
 * @param type  type de la valeur, {@code STRING} par défaut
 * @param value valeur sous forme de texte, normalisée selon {@code type}
 * @param scope credentials concernés, {@code ALL} par défaut
 */
public record ClaimInputDTO(String name, ClaimType type, String value, ClaimScope scope) {
}
