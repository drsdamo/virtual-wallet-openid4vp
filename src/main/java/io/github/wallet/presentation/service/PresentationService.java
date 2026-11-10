package io.github.wallet.presentation.service;

import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject;
import io.github.wallet.credentials.service.CredentialStore;
import io.github.wallet.presentation.dto.HttpExchangeDTO;
import io.github.wallet.presentation.support.DcqlMatcher;
import io.github.wallet.presentation.support.Fault;
import io.github.wallet.presentation.support.PresentationBuilder;
import io.github.wallet.presentation.support.QueryMatch;
import io.github.wallet.presentation.support.openid4vp.DispatchResult;
import io.github.wallet.presentation.support.openid4vp.OpenId4VpWalletClient;
import io.github.wallet.presentation.support.openid4vp.WalletResolution;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Orchestre la résolution, le matching DCQL, la construction des présentations et leur envoi. */
public class PresentationService {

    private static final Logger log = LogManager.getLogger(PresentationService.class);

    private final OpenId4VpWalletClient client;
    private final CredentialStore store;
    private final PresentationBuilder builder;

    public PresentationService(OpenId4VpWalletClient client, CredentialStore store) {
        this.client = client;
        this.store = store;
        this.builder = new PresentationBuilder();
    }

    /** Résout la requête et choisit la première identité qui y répond. */
    public PendingPresentation resolve(String authorizationRequestUri, String traceId) {
        return resolve(authorizationRequestUri, traceId, null);
    }

    /**
     * Résout la requête et choisit l'identité qui y répond.
     *
     * @param traceId    identifiant de corrélation des échanges HTTP
     * @param identityId ne présenter que les credentials de cette identité ; {@code null} = la première qui répond
     */
    public PendingPresentation resolve(String authorizationRequestUri, String traceId, String identityId) {
        log.debug("[{}] Resolving {}", traceId, authorizationRequestUri);
        return switch (client.resolve(authorizationRequestUri, traceId)) {
            case WalletResolution.Invalid invalid -> new PendingPresentation.Invalid(traceId, invalid);
            case WalletResolution.Valid valid -> {
                ResolvedRequestObject request = valid.request();
                IdentityMatch chosen = matchIdentity(request, identityId);
                chosen.matches().forEach(m -> log.debug("[{}] DCQL query {} -> {}", traceId, m.queryId(),
                        m.credential() != null ? m.credential().getId() : "no match: " + m.reason()));
                log.info("[{}] Request matched by identity {} ({}/{} queries)", traceId, chosen.identityId(),
                        chosen.satisfied(), chosen.matches().size());
                yield new PendingPresentation.Valid(traceId, request, client.describe(request), chosen.matches(),
                        chosen.identityId());
            }
        };
    }

    /** Correspondances DCQL des credentials d'une identité. */
    private record IdentityMatch(String identityId, List<QueryMatch> matches) {

        long satisfied() {
            return matches.stream().filter(m -> m.credential() != null).count();
        }

        boolean complete() {
            return satisfied() == matches.size();
        }
    }

    /**
     * Ne mélange jamais deux identités dans une réponse : prend {@code identityId}, sinon la première identité qui
     * répond à toutes les requêtes, sinon celle qui répond au plus grand nombre.
     */
    private IdentityMatch matchIdentity(ResolvedRequestObject request, String identityId) {
        List<String> candidates = identityId != null ? List.of(identityId) : store.identityIds();
        List<IdentityMatch> results = candidates.stream()
                .map(id -> new IdentityMatch(id, new DcqlMatcher(store.forIdentity(id)).match(request.getQuery())))
                .toList();
        return results.stream().filter(IdentityMatch::complete).findFirst()
                // en cas d'égalité, la première identité l'emporte
                .or(() -> results.stream().reduce((a, b) -> b.satisfied() > a.satisfied() ? b : a))
                .orElseGet(() -> new IdentityMatch(null, new DcqlMatcher(List.of()).match(request.getQuery())));
    }

    /** Envoie une présentation correcte pour chaque requête satisfaisable. */
    public DispatchResult accept(PendingPresentation.Valid pending) {
        return accept(pending, Set.of());
    }

    /** Envoie une présentation pour chaque requête satisfaisable, avec les {@code faults} demandés. */
    public DispatchResult accept(PendingPresentation.Valid pending, Set<Fault> faults) {
        Map<String, List<String>> vpToken = new LinkedHashMap<>();
        for (QueryMatch match : pending.matches()) {
            if (match.credential() == null) {
                continue;
            }
            // Défaut VP_TOKEN_WRONG_QUERY_ID : le vp_token est indexé par un id inconnu du verifier.
            String key = faults.contains(Fault.VP_TOKEN_WRONG_QUERY_ID) ? match.queryId() + "-unknown" : match.queryId();
            vpToken.put(key, List.of(builder.build(pending.request(), match, faults)));
        }
        if (vpToken.isEmpty()) {
            throw new IllegalArgumentException("no credential matches the request");
        }
        log.info("[{}] Submitting vp_token for queries {} (faults: {})", pending.traceId(), vpToken.keySet(), faults);
        return client.submit(pending.request(), vpToken, pending.traceId());
    }

    /** Refuse la requête ({@code access_denied}). */
    public DispatchResult decline(PendingPresentation.Valid pending) {
        return client.decline(pending.request(), pending.traceId());
    }

    /** Renvoie l'erreur d'une requête invalide ; {@code null} si la lib ne sait pas où l'envoyer. */
    public DispatchResult reportError(PendingPresentation.Invalid pending) {
        return client.reportError(pending.resolution(), pending.traceId());
    }

    /** Échanges HTTP d'une présentation. */
    public List<HttpExchangeDTO> exchanges(String traceId) {
        return client.getExchangeLog().forTrace(traceId);
    }

    /** Tous les échanges HTTP récents. */
    public List<HttpExchangeDTO> allExchanges() {
        return client.getExchangeLog().all();
    }
}
