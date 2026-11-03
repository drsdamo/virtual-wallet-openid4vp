package io.github.wallet.presentation.service;

import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject;
import io.github.wallet.presentation.dto.VerifierInfoDTO;
import io.github.wallet.presentation.support.QueryMatch;
import io.github.wallet.presentation.support.openid4vp.WalletResolution;
import java.util.List;

/** Requête d'autorisation résolue, en attente de la décision du porteur. */
public sealed interface PendingPresentation {

    /** Corrèle les échanges HTTP de cette présentation dans le journal. */
    String traceId();

    /**
     * Requête valide : le verifier est authentifié et les requêtes DCQL ont été confrontées aux credentials.
     *
     * @param identityId identité dont les credentials sont présentés
     */
    record Valid(String traceId, ResolvedRequestObject request, VerifierInfoDTO verifier, List<QueryMatch> matches,
                 String identityId) implements PendingPresentation {

        public String nonce() {
            return request.getNonce();
        }

        public String state() {
            return request.getState();
        }

        /** Toutes les requêtes de credential ont une réponse. Les {@code credential_sets} ne sont pas évalués. */
        public boolean satisfiable() {
            return matches.stream().allMatch(m -> m.credential() != null);
        }
    }

    /** Requête rejetée par la lib EUDI (signature, client_id, confiance, paramètres…). */
    record Invalid(String traceId, WalletResolution.Invalid resolution) implements PendingPresentation {

        public String error() {
            return resolution.errorDescription();
        }

        /** La lib sait où envoyer une réponse d'erreur. */
        public boolean dispatchable() {
            return resolution.resolution().getDispatchDetails() != null;
        }
    }
}
