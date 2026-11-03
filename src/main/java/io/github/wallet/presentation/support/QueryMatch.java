package io.github.wallet.presentation.support;

import io.github.wallet.credentials.support.WalletCredential;
import java.util.List;

/**
 * Résultat du matching d'une requête de credential DCQL avec le wallet.
 *
 * @param requestedTypes {@code vct_values} ou {@code doctype_value} demandés par le verifier
 * @param credential     credential retenu, ou {@code null} si le wallet ne peut pas satisfaire la requête
 * @param disclosedPaths chemins des claims divulgués ; {@code null} = credential entier (pas de {@code claims})
 * @param reason         pourquoi la requête n'est pas satisfaisable, quand {@code credential} est {@code null}
 */
public record QueryMatch(String queryId, String format, List<String> requestedTypes, WalletCredential credential,
                         List<List<Object>> disclosedPaths, String reason) {
}
