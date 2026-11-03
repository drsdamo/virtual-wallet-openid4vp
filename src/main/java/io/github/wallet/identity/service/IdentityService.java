package io.github.wallet.identity.service;

import io.github.wallet.credentials.service.CredentialStore;
import io.github.wallet.credentials.support.TestPersona;
import io.github.wallet.identity.dto.ClaimInputDTO;
import io.github.wallet.identity.dto.IdentityClaimDTO;
import io.github.wallet.identity.dto.IdentityDTO;
import io.github.wallet.identity.dto.IdentityInputDTO;
import io.github.wallet.identity.service.dao.IdentityDao;
import io.github.wallet.identity.support.ClaimScope;
import io.github.wallet.identity.support.ClaimType;
import io.github.wallet.identity.support.NotFoundException;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.transaction.annotation.Transactional;

/**
 * CRUD sur les identités et leurs claims, avec validation des entrées.
 * <p>
 * Chaque modification réémet les credentials de l'identité : ce que le wallet présente reflète toujours la base.
 */
public class IdentityService {

    private static final Logger log = LogManager.getLogger(IdentityService.class);

    /** Noms simples, ou chemins pointés pour les objets SD-JWT imbriqués ({@code address.locality}). */
    private static final Pattern CLAIM_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*");

    /** Posés par l'émetteur lui-même : un claim additionnel ne peut pas les remplacer. */
    private static final Set<String> RESERVED = Set.of(
            "iss", "vct", "iat", "exp", "nbf", "cnf", "status", "_sd", "_sd_alg", "sub",
            "family_name", "given_name", "birthdate", "birth_date", "issuing_authority", "issuing_country",
            "personal_administrative_number", "age_equal_or_over", "age_in_years", "age_over_18",
            "date_of_issuance", "date_of_expiry");

    private final IdentityDao dao;
    private final CredentialStore store;
    private final TestPersona persona;

    public IdentityService(IdentityDao dao, CredentialStore store, TestPersona persona) {
        this.dao = dao;
        this.store = store;
        this.persona = persona;
    }

    /** Au démarrage : crée l'identité de test si la base est vide, puis émet les credentials de chaque identité. */
    @EventListener(ApplicationReadyEvent.class)
    public void initialise() {
        if (dao.count() == 0) {
            dao.insert(persona.identity());
            log.info("Empty wallet database: created test identity {} {}", TestPersona.GIVEN_NAME, TestPersona.FAMILY_NAME);
        }
        dao.findAll().forEach(store::issue);
        log.info("Issued credentials for {} identities", dao.count());
    }

    /** Toutes les identités, avec leurs claims. */
    public List<IdentityDTO> findAll() {
        return dao.findAll();
    }

    /**
     * @throws NotFoundException si l'identité n'existe pas
     */
    public IdentityDTO get(String id) {
        return dao.findById(id).orElseThrow(() -> new NotFoundException("identity " + id));
    }

    /**
     * Crée une identité et ses claims, puis émet ses credentials.
     *
     * @throws IllegalArgumentException si un champ obligatoire manque ou si un claim est invalide
     */
    @Transactional
    public IdentityDTO create(IdentityInputDTO input) {
        validate(input);
        Instant now = Instant.now();
        List<IdentityClaimDTO> claims = input.claims() == null ? List.of()
                : input.claims().stream().map(c -> claim(UUID.randomUUID().toString(), c)).toList();
        ensureUnique(claims);
        IdentityDTO identity = new IdentityDTO(UUID.randomUUID().toString(), input.familyName().trim(),
                input.givenName().trim(), input.birthDate(), claims, now, now);
        dao.insert(identity);
        log.info("Created identity {} ({} {}, {} claims)", identity.id(), identity.givenName(), identity.familyName(),
                claims.size());
        return reissue(identity.id());
    }

    /** Modifie nom, prénom et date de naissance ; les claims se gèrent avec les méthodes dédiées. */
    @Transactional
    public IdentityDTO update(String id, IdentityInputDTO input) {
        validate(input);
        if (!dao.update(id, input.familyName().trim(), input.givenName().trim(), input.birthDate(), Instant.now())) {
            throw new NotFoundException("identity " + id);
        }
        log.info("Updated identity {}", id);
        return reissue(id);
    }

    /** Supprime l'identité, ses claims (cascade) et ses credentials. */
    @Transactional
    public void delete(String id) {
        if (!dao.delete(id)) {
            throw new NotFoundException("identity " + id);
        }
        store.remove(id);
        log.info("Deleted identity {} and its credentials", id);
    }

    /** Ajoute un claim à l'identité, après contrôle de son nom et de son unicité. */
    @Transactional
    public IdentityDTO addClaim(String identityId, ClaimInputDTO input) {
        IdentityDTO identity = get(identityId);
        IdentityClaimDTO claim = claim(UUID.randomUUID().toString(), input);
        ensureUnique(concat(identity.claims(), claim));
        dao.insertClaim(identityId, claim);
        dao.touch(identityId, Instant.now());
        log.info("Identity {}: added claim {} ({}, {})", identityId, claim.name(), claim.type(), claim.scope());
        return reissue(identityId);
    }

    /** Remplace un claim ; l'unicité est vérifiée sans tenir compte de sa version précédente. */
    @Transactional
    public IdentityDTO updateClaim(String identityId, String claimId, ClaimInputDTO input) {
        IdentityDTO identity = get(identityId);
        IdentityClaimDTO claim = claim(claimId, input);
        ensureUnique(concat(identity.claims().stream().filter(c -> !c.id().equals(claimId)).toList(), claim));
        if (!dao.updateClaim(identityId, claim)) {
            throw new NotFoundException("claim " + claimId);
        }
        dao.touch(identityId, Instant.now());
        log.info("Identity {}: updated claim {} ({})", identityId, claimId, claim.name());
        return reissue(identityId);
    }

    /** Supprime un claim de l'identité. */
    @Transactional
    public IdentityDTO deleteClaim(String identityId, String claimId) {
        if (!dao.deleteClaim(identityId, claimId)) {
            throw new NotFoundException("claim " + claimId);
        }
        dao.touch(identityId, Instant.now());
        log.info("Identity {}: deleted claim {}", identityId, claimId);
        return reissue(identityId);
    }

    /** Relit l'identité en base et réémet ses credentials. */
    private IdentityDTO reissue(String id) {
        IdentityDTO identity = get(id);
        store.issue(identity);
        log.debug("Re-issued credentials of identity {}: {}", id, identity);
        return identity;
    }

    /** Champs obligatoires et date de naissance dans le passé. */
    private void validate(IdentityInputDTO input) {
        if (input == null || blank(input.familyName()) || blank(input.givenName()) || input.birthDate() == null) {
            throw new IllegalArgumentException("familyName, givenName and birthDate are required");
        }
        if (input.birthDate().isAfter(LocalDate.now())) {
            throw new IllegalArgumentException("birthDate cannot be in the future");
        }
    }

    /** Valide l'entrée et construit le claim, avec type et portée par défaut et valeur normalisée. */
    private IdentityClaimDTO claim(String id, ClaimInputDTO input) {
        if (input == null || blank(input.name())) {
            throw new IllegalArgumentException("claim name is required");
        }
        String name = input.name().trim();
        if (!CLAIM_NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("invalid claim name '" + name + "' (letters, digits, _ and . for nesting)");
        }
        if (RESERVED.contains(name) || RESERVED.contains(name.split("\\.")[0])) {
            throw new IllegalArgumentException("'" + name + "' is set by the issuer and cannot be overridden");
        }
        ClaimType type = input.type() == null ? ClaimType.STRING : input.type();
        ClaimScope scope = input.scope() == null ? ClaimScope.ALL : input.scope();
        if (scope != ClaimScope.SD_JWT && name.contains(".")) {
            throw new IllegalArgumentException("dotted names are only supported for SD_JWT claims");
        }
        return new IdentityClaimDTO(id, name, type, type.normalise(input.value()), scope);
    }

    /** Un nom de claim n'apparaît qu'une fois par credential : ALL entre en conflit avec SD_JWT et avec MDOC. */
    private void ensureUnique(List<IdentityClaimDTO> claims) {
        for (ClaimScope target : List.of(ClaimScope.SD_JWT, ClaimScope.MDOC)) {
            List<String> names = claims.stream()
                    .filter(c -> c.scope() == ClaimScope.ALL || c.scope() == target).map(IdentityClaimDTO::name).toList();
            names.stream().filter(n -> names.indexOf(n) != names.lastIndexOf(n)).findFirst().ifPresent(n -> {
                throw new IllegalArgumentException("claim '" + n + "' is defined twice for " + target);
            });
            // Un chemin SD-JWT ne peut pas être à la fois une valeur et un objet : address et address.locality
            names.stream().filter(n -> names.stream().anyMatch(o -> o.startsWith(n + "."))).findFirst().ifPresent(n -> {
                throw new IllegalArgumentException("claim '" + n + "' is both a value and an object");
            });
        }
    }

    private List<IdentityClaimDTO> concat(List<IdentityClaimDTO> claims, IdentityClaimDTO extra) {
        return java.util.stream.Stream.concat(claims.stream(), java.util.stream.Stream.of(extra)).toList();
    }

    private boolean blank(String s) {
        return s == null || s.isBlank();
    }
}
