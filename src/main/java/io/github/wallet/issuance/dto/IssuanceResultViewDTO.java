package io.github.wallet.issuance.dto;

import io.github.wallet.issuance.support.IssuanceFault;
import io.github.wallet.issuance.support.IssuanceStep;
import io.github.wallet.presentation.dto.HttpExchangeDTO;
import java.util.List;
import java.util.Set;

/**
 * Issue d'une émission. Un échec peut suivre des credentials déjà reçus (offre à plusieurs credentials).
 *
 * @param warnings anomalies non bloquantes (credential mal lié, pre-authorized_code rejouable…)
 * @param error    message d'erreur, {@code null} en cas de succès ; {@code step}, {@code status} et
 *                 {@code oauthError} la précisent
 */
public record IssuanceResultViewDTO(String id, boolean success, List<ReceivedCredentialViewDTO> credentials,
                                    List<String> warnings, String error, IssuanceStep step, Integer status,
                                    String oauthError, Set<IssuanceFault> faults, List<HttpExchangeDTO> exchanges) {
}
