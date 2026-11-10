package io.github.wallet.issuance.web;

import io.github.wallet.issuance.dto.AcceptOfferRequestDTO;
import io.github.wallet.issuance.dto.IssuanceFaultViewDTO;
import io.github.wallet.issuance.dto.IssuanceResultViewDTO;
import io.github.wallet.issuance.dto.OfferedCredentialDTO;
import io.github.wallet.issuance.dto.PendingOfferViewDTO;
import io.github.wallet.issuance.dto.ReceivedCredentialViewDTO;
import io.github.wallet.issuance.dto.ResolveOfferRequestDTO;
import io.github.wallet.issuance.service.IssuanceService;
import io.github.wallet.issuance.service.PendingOffer;
import io.github.wallet.issuance.service.PendingOfferRegistry;
import io.github.wallet.issuance.support.CredentialConfiguration;
import io.github.wallet.issuance.support.IssuanceException;
import io.github.wallet.issuance.support.IssuanceFault;
import io.github.wallet.presentation.dto.HttpExchangeDTO;

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
 * Réception de credentials par OpenID4VCI côté porteur : {@code POST /api/offers} lit l'offre et la met en attente,
 * {@code accept} déroule l'émission. Les credentials reçus sont listés sous {@code /api/received-credentials}.
 */
@RestController
@RequestMapping("/api")
class IssuanceController {

    private static final Logger log = LogManager.getLogger(IssuanceController.class);

    private final IssuanceService service;
    private final PendingOfferRegistry pending;

    IssuanceController(IssuanceService service, PendingOfferRegistry pending) {
        this.service = service;
        this.pending = pending;
    }

    /** Lit l'offre, récupère les metadata de l'émetteur et met l'offre en attente du porteur. */
    @PostMapping("/offers")
    PendingOfferViewDTO resolve(@RequestBody ResolveOfferRequestDTO body) {
        if (body.offer() == null || body.offer().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "offer is required");
        }
        String id = UUID.randomUUID().toString();
        return toView(pending.add(service.resolve(body.offer(), id)));
    }

    /** Offres en attente, de la plus ancienne à la plus récente. */
    @GetMapping("/offers/pending")
    List<PendingOfferViewDTO> pendingOffers() {
        return pending.all().stream().map(this::toView).toList();
    }

    @GetMapping("/offers/{id}")
    PendingOfferViewDTO pendingOffer(@PathVariable String id) {
        return pending.get(id).map(this::toView).orElseThrow(() -> unknown(id));
    }

    /** Ignore l'offre : OpenID4VCI ne prévoit pas de refus explicite, l'émetteur n'est pas prévenu. */
    @DeleteMapping("/offers/{id}")
    ResponseEntity<Void> dismiss(@PathVariable String id) {
        if (!pending.remove(id)) {
            throw unknown(id);
        }
        log.info("Credential offer {} dismissed by the holder", id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/offers/faults")
    List<IssuanceFaultViewDTO> faults() {
        return Arrays.stream(IssuanceFault.values()).map(f -> new IssuanceFaultViewDTO(f, f.getDescription())).toList();
    }

    /** Déroule l'émission ; 502 si l'émetteur la refuse, avec ce qui a déjà été reçu et les échanges. */
    @PostMapping("/offers/{id}/accept")
    ResponseEntity<IssuanceResultViewDTO> accept(@PathVariable String id, @RequestBody(required = false) AcceptOfferRequestDTO body) {
        AcceptOfferRequestDTO request = body == null ? new AcceptOfferRequestDTO(null, null, null) : body;
        Set<IssuanceFault> faults = request.faults() == null ? Set.of() : Set.copyOf(request.faults());
        PendingOffer.Valid offer = take(id);
        if (!faults.isEmpty()) {
            log.info("Credential offer {} accepted with injected faults {}", id, faults);
        }
        IssuanceService.Outcome outcome;
        try {
            outcome = service.accept(offer, request.txCode(), request.identityId(), faults);
        } catch (IllegalArgumentException e) {
            pending.add(offer); // entrée du porteur à corriger : l'offre reste disponible
            throw e;
        }
        IssuanceException e = outcome.error();
        var view = new IssuanceResultViewDTO(id, outcome.success(), outcome.credentials(), outcome.warnings(),
                e == null ? null : e.getMessage(), e == null ? null : e.getStep(), e == null ? null : e.getStatus(),
                e == null ? null : e.getError(), faults, service.exchanges(id));
        return ResponseEntity.status(outcome.success() ? HttpStatus.OK : HttpStatus.BAD_GATEWAY).body(view);
    }

    @GetMapping("/offers/{id}/exchanges")
    List<HttpExchangeDTO> exchanges(@PathVariable String id) {
        return service.exchanges(id);
    }

    /** Tous les échanges récents avec des émetteurs. */
    @GetMapping("/offers/exchanges")
    List<HttpExchangeDTO> allExchanges() {
        return service.allExchanges();
    }

    @GetMapping("/received-credentials")
    List<ReceivedCredentialViewDTO> received() {
        return service.received();
    }

    @DeleteMapping("/received-credentials/{id}")
    ResponseEntity<Void> deleteReceived(@PathVariable String id) {
        if (!service.delete(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown received credential " + id);
        }
        return ResponseEntity.noContent().build();
    }

    // ----------------------------------------------------------------

    private PendingOfferViewDTO toView(PendingOfferRegistry.Waiting w) {
        String id = w.offer().traceId();
        return switch (w.offer()) {
            case PendingOffer.Valid v -> new PendingOfferViewDTO(id, w.receivedAt(), true, v.offer().credentialIssuer(),
                    v.issuer().displayName(), v.offer().credentialConfigurationIds().stream().map(c -> offered(v, c)).toList(),
                    v.offer().txCode(), v.authorizationServer().tokenEndpoint(), v.issuer().credentialEndpoint(),
                    v.issuer().nonceEndpoint(), v.authorizationServer().dpopSigningAlgs(), v.offer().json(), null, null,
                    service.exchanges(id));
            case PendingOffer.Invalid i -> new PendingOfferViewDTO(id, w.receivedAt(), false, null, null, null, null,
                    null, null, null, null, null, i.error().getMessage(), i.error().getStep(), service.exchanges(id));
        };
    }

    private OfferedCredentialDTO offered(PendingOffer.Valid v, String configurationId) {
        CredentialConfiguration c = v.issuer().configurations().get(configurationId);
        String reason = service.unsupportedReason(configurationId, c);
        return c == null ? new OfferedCredentialDTO(configurationId, null, null, null, false, false, reason)
                : new OfferedCredentialDTO(configurationId, c.format(), c.type(), c.displayName(), c.proofRequired(),
                        reason == null, reason);
    }

    private PendingOffer.Valid take(String id) {
        try {
            return pending.take(id);
        } catch (NoSuchElementException e) {
            throw unknown(id);
        } catch (IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        }
    }

    private ResponseStatusException unknown(String id) {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown or already processed offer " + id);
    }

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String, String>> status(ResponseStatusException e) {
        return ResponseEntity.status(e.getStatusCode()).body(Map.of("error", String.valueOf(e.getReason())));
    }

    /** Entrée invalide (tx_code manquant, identité inconnue) : 400. */
    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
    }
}
