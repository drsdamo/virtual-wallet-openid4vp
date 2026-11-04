package io.github.wallet.presentation.web;

import io.github.wallet.presentation.dto.AcceptRequestDTO;
import io.github.wallet.presentation.dto.ClaimViewDTO;
import io.github.wallet.presentation.dto.FaultViewDTO;
import io.github.wallet.presentation.dto.HttpExchangeDTO;
import io.github.wallet.presentation.dto.PendingViewDTO;
import io.github.wallet.presentation.dto.QueryViewDTO;
import io.github.wallet.presentation.dto.ResolveRequestDTO;
import io.github.wallet.presentation.dto.ResultViewDTO;
import io.github.wallet.presentation.service.PendingPresentation;
import io.github.wallet.presentation.service.PendingPresentationRegistry;
import io.github.wallet.presentation.service.PresentationService;
import io.github.wallet.presentation.support.ClaimValueReader;
import io.github.wallet.presentation.support.Fault;
import io.github.wallet.presentation.support.QueryMatch;
import io.github.wallet.presentation.support.openid4vp.DispatchResult;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Flux de présentation côté porteur : {@code POST /api/presentations} reçoit une requête et la met en attente,
 * puis {@code accept}, {@code decline} ou {@code report-error} y répond.
 * <p>
 * Les requêtes en attente sont gardées en mémoire ({@link PendingPresentationRegistry}) jusqu'à leur réponse ;
 * l'IHM les liste via {@code GET /api/presentations/pending} pour demander son accord au porteur.
 */
@RestController
@RequestMapping("/api/presentations")
class PresentationController {

    private static final Logger log = LogManager.getLogger(PresentationController.class);

    private final PresentationService service;
    private final PendingPresentationRegistry pending;
    private final ClaimValueReader claimValues;

    PresentationController(PresentationService service, PendingPresentationRegistry pending,
                           ClaimValueReader claimValues) {
        this.service = service;
        this.pending = pending;
        this.claimValues = claimValues;
    }

    /** Résout et valide la requête, cherche les credentials qui y répondent, et la met en attente du porteur. */
    @PostMapping
    PendingViewDTO resolve(@RequestBody ResolveRequestDTO body) {
        if (body.requestUri() == null || body.requestUri().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "requestUri is required");
        }
        String id = UUID.randomUUID().toString();
        PendingPresentation result = service.resolve(body.requestUri().trim(), id,
                body.identityId() == null || body.identityId().isBlank() ? null : body.identityId());
        switch (result) {
            case PendingPresentation.Valid v -> log.info("Resolved request {} from {} ({}), {} credential queries",
                    id, v.verifier().clientId(), v.verifier().responseMode(), v.matches().size());
            case PendingPresentation.Invalid i -> log.warn("Invalid authorization request {}: {}", id, i.error());
        }
        return toView(pending.add(result));
    }

    /** Demandes en attente de la décision du porteur, de la plus ancienne à la plus récente. */
    @GetMapping("/pending")
    List<PendingViewDTO> pendingPresentations() {
        return pending.all().stream().map(this::toView).toList();
    }

    /** Une demande en attente ; 404 si elle est inconnue ou déjà répondue. */
    @GetMapping("/{id}")
    PendingViewDTO pendingPresentation(@PathVariable String id) {
        return pending.get(id).map(this::toView).orElseThrow(() -> unknown(id));
    }

    /** Ignore une demande sans rien répondre au verifier (par ex. requête invalide qu'on ne peut pas renvoyer). */
    @DeleteMapping("/{id}")
    ResponseEntity<Void> dismiss(@PathVariable String id) {
        if (!pending.remove(id)) {
            throw unknown(id);
        }
        log.info("Presentation {} dismissed by the holder", id);
        return ResponseEntity.noContent().build();
    }

    /** Défauts injectables dans {@code accept}. */
    @GetMapping("/faults")
    List<FaultViewDTO> faults() {
        return Arrays.stream(Fault.values()).map(f -> new FaultViewDTO(f, f.getFormat(), f.getDescription())).toList();
    }

    /** Envoie la présentation au verifier, avec les défauts demandés. */
    @PostMapping("/{id}/accept")
    ResultViewDTO accept(@PathVariable String id, @RequestBody(required = false) AcceptRequestDTO body) {
        Set<Fault> faults = body == null || body.faults() == null ? Set.of() : Set.copyOf(body.faults());
        if (!faults.isEmpty()) {
            log.info("Presentation {} sent with injected faults {}", id, faults);
        }
        return result(id, service.accept(take(id, PendingPresentation.Valid.class), faults), faults);
    }

    /** Refuse : envoie {@code access_denied} au verifier. */
    @PostMapping("/{id}/decline")
    ResultViewDTO decline(@PathVariable String id) {
        log.info("Presentation {} declined by the holder", id);
        return result(id, service.decline(take(id, PendingPresentation.Valid.class)), Set.of());
    }

    /** Renvoie au verifier l'erreur d'une requête invalide ; 422 si la lib ne sait pas où l'envoyer. */
    @PostMapping("/{id}/report-error")
    ResponseEntity<ResultViewDTO> reportError(@PathVariable String id) {
        log.info("Presentation {}: reporting the resolution error to the verifier", id);
        DispatchResult result = service.reportError(take(id, PendingPresentation.Invalid.class));
        return result == null ? ResponseEntity.unprocessableEntity().build() : ResponseEntity.ok(result(id, result, Set.of()));
    }

    /** Échanges HTTP avec le verifier pour une présentation (disponibles aussi après la réponse). */
    @GetMapping("/{id}/exchanges")
    List<HttpExchangeDTO> exchanges(@PathVariable String id) {
        return service.exchanges(id);
    }

    /** Tous les échanges HTTP récents avec des verifiers, du plus ancien au plus récent. */
    @GetMapping("/exchanges")
    List<HttpExchangeDTO> allExchanges() {
        return service.allExchanges();
    }

    /** Demande en attente → DTO exposé par l'API. */
    private PendingViewDTO toView(PendingPresentationRegistry.Waiting w) {
        String id = w.presentation().traceId();
        return switch (w.presentation()) {
            case PendingPresentation.Valid v -> new PendingViewDTO(id, w.receivedAt(), true, v.identityId(),
                    v.verifier(), v.nonce(), v.state(), v.matches().stream().map(this::toView).toList(),
                    v.satisfiable(), null, null, service.exchanges(id));
            case PendingPresentation.Invalid i -> new PendingViewDTO(id, w.receivedAt(), false, null, null, null, null,
                    null, null, i.error(), i.dispatchable(), service.exchanges(id));
        };
    }

    /** Correspondance DCQL → DTO exposé par l'API, avec les valeurs qui seront divulguées. */
    private QueryViewDTO toView(QueryMatch m) {
        List<ClaimViewDTO> claims = m.credential() == null || m.disclosedPaths() == null ? null
                : m.disclosedPaths().stream()
                        .map(p -> new ClaimViewDTO(p, claimValues.read(m.credential().getClaims(), p)))
                        .toList();
        return new QueryViewDTO(m.queryId(), m.format(), m.requestedTypes(),
                m.credential() == null ? null : m.credential().getId(), m.disclosedPaths(), claims, m.reason());
    }

    /** Trace l'issue et construit la réponse de l'API. */
    private ResultViewDTO result(String id, DispatchResult r, Set<Fault> faults) {
        log.info("Presentation {}: verifier {} the response{}", id, r.accepted() ? "accepted" : "rejected",
                r.redirectUri() == null ? "" : ", redirect_uri " + r.redirectUri());
        return new ResultViewDTO(id, r.accepted(), r.redirectUri(), faults, service.exchanges(id));
    }

    /**
     * Une requête n'est répondue qu'une fois : elle est retirée des requêtes en attente (404 si elle n'y est plus).
     * Si elle n'a pas le type attendu (valide / invalide), elle y reste et l'appel échoue en 409.
     */
    private <T extends PendingPresentation> T take(String id, Class<T> type) {
        try {
            return pending.take(id, type);
        } catch (NoSuchElementException e) {
            throw unknown(id);
        } catch (IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        }
    }

    private ResponseStatusException unknown(String id) {
        log.debug("Presentation {} unknown or already answered", id);
        return new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown or already answered request " + id);
    }

    /** En général le verifier qui refuse la réponse (HTTP 4xx/5xx sur la response_uri) : 502. */
    @ExceptionHandler(Exception.class)
    ResponseEntity<Map<String, String>> dispatchFailure(Exception e) {
        if (e instanceof ResponseStatusException rse) {
            return ResponseEntity.status(rse.getStatusCode()).body(Map.of("error", String.valueOf(rse.getReason())));
        }
        log.warn("Presentation failed", e);
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
    }

    /** Entrée invalide : 400. */
    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
    }
}
