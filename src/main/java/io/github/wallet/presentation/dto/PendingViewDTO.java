package io.github.wallet.presentation.dto;

import java.time.Instant;
import java.util.List;

/**
 * Requête résolue, en attente de la décision du porteur.
 * Une requête valide porte le verifier et les correspondances DCQL ; une requête invalide porte l'erreur.
 *
 * @param receivedAt date de réception par le wallet
 */
public record PendingViewDTO(String id, Instant receivedAt, boolean valid, String identityId, VerifierInfoDTO verifier,
                             String nonce, String state, List<QueryViewDTO> queries, Boolean satisfiable, String error,
                             Boolean dispatchable, List<HttpExchangeDTO> exchanges) {
}
