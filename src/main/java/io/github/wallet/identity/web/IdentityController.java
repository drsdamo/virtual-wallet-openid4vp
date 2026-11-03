package io.github.wallet.identity.web;

import io.github.wallet.credentials.service.CredentialStore;
import io.github.wallet.identity.dto.ClaimInputDTO;
import io.github.wallet.identity.dto.CredentialRefDTO;
import io.github.wallet.identity.dto.IdentityDTO;
import io.github.wallet.identity.dto.IdentityInputDTO;
import io.github.wallet.identity.dto.IdentityViewDTO;
import io.github.wallet.identity.service.IdentityService;
import io.github.wallet.identity.support.NotFoundException;

import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * API REST {@code /api/identities} : CRUD sur les identités et leurs claims additionnels.
 * Chaque modification réémet les credentials de l'identité ; les réponses les listent.
 */
@RestController
@RequestMapping("/api/identities")
class IdentityController {

    private static final Logger log = LogManager.getLogger(IdentityController.class);

    private final IdentityService service;
    private final CredentialStore store;

    IdentityController(IdentityService service, CredentialStore store) {
        this.service = service;
        this.store = store;
    }

    /** Liste les identités. */
    @GetMapping
    List<IdentityViewDTO> list() {
        return service.findAll().stream().map(this::view).toList();
    }

    /** Lit une identité (404 si inconnue). */
    @GetMapping("/{id}")
    IdentityViewDTO get(@PathVariable String id) {
        return view(service.get(id));
    }

    /** Crée une identité (201). */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    IdentityViewDTO create(@RequestBody IdentityInputDTO input) {
        return view(service.create(input));
    }

    /** Modifie nom, prénom et date de naissance. */
    @PutMapping("/{id}")
    IdentityViewDTO update(@PathVariable String id, @RequestBody IdentityInputDTO input) {
        return view(service.update(id, input));
    }

    /** Supprime une identité et ses credentials (204). */
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void delete(@PathVariable String id) {
        service.delete(id);
    }

    /** Ajoute un claim (201). */
    @PostMapping("/{id}/claims")
    @ResponseStatus(HttpStatus.CREATED)
    IdentityViewDTO addClaim(@PathVariable String id, @RequestBody ClaimInputDTO input) {
        return view(service.addClaim(id, input));
    }

    /** Modifie un claim. */
    @PutMapping("/{id}/claims/{claimId}")
    IdentityViewDTO updateClaim(@PathVariable String id, @PathVariable String claimId, @RequestBody ClaimInputDTO input) {
        return view(service.updateClaim(id, claimId, input));
    }

    /** Supprime un claim. */
    @DeleteMapping("/{id}/claims/{claimId}")
    IdentityViewDTO deleteClaim(@PathVariable String id, @PathVariable String claimId) {
        return view(service.deleteClaim(id, claimId));
    }

    /** Identité + références des credentials émis pour elle. */
    private IdentityViewDTO view(IdentityDTO identity) {
        return new IdentityViewDTO(identity, store.forIdentity(identity.id()).stream()
                .map(c -> new CredentialRefDTO(c.getId(), c.getFormat(), c.getType())).toList());
    }

    /** Identité ou claim inconnu : 404 avec le message. */
    @ExceptionHandler(NotFoundException.class)
    ResponseEntity<Map<String, String>> notFound(RuntimeException e) {
        log.info("Not found: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
    }

    /** Entrée invalide : 400 avec le message de validation. */
    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Map<String, String>> badRequest(RuntimeException e) {
        log.info("Rejected identity input: {}", e.getMessage());
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
