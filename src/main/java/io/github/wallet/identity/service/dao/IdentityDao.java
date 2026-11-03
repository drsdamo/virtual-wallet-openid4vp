package io.github.wallet.identity.service.dao;

import io.github.wallet.identity.dto.IdentityClaimDTO;
import io.github.wallet.identity.dto.IdentityDTO;
import io.github.wallet.identity.support.ClaimScope;
import io.github.wallet.identity.support.ClaimType;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.annotation.Transactional;

/**
 * Accès SQLite aux tables {@code identity} et {@code identity_claim}, via {@link JdbcTemplate}.
 * <p>
 * Pas d'ORM : deux tables et des requêtes simples ne le justifient pas. Les dates sont stockées en texte ISO-8601,
 * format que SQLite trie correctement.
 */
public class IdentityDao {

    private static final Logger log = LogManager.getLogger(IdentityDao.class);

    private final JdbcTemplate jdbc;

    /** Ligne {@code identity_claim} → claim. */
    private final RowMapper<IdentityClaimDTO> claimMapper = (rs, n) -> new IdentityClaimDTO(
            rs.getString("id"), rs.getString("name"), ClaimType.valueOf(rs.getString("type")),
            rs.getString("value"), ClaimScope.valueOf(rs.getString("scope")));

    public IdentityDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Toutes les identités, de la plus ancienne à la plus récente, avec leurs claims. */
    public List<IdentityDTO> findAll() {
        // Deux requêtes plutôt qu'une jointure : évite de regrouper les lignes à la main.
        Map<String, List<IdentityClaimDTO>> claims = jdbc.query("SELECT * FROM identity_claim ORDER BY name",
                        (rs, n) -> Map.entry(rs.getString("identity_id"), claimMapper.mapRow(rs, n)))
                .stream()
                .collect(Collectors.groupingBy(Map.Entry::getKey,
                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())));
        return jdbc.query("SELECT * FROM identity ORDER BY created_at",
                identityMapper(id -> claims.getOrDefault(id, List.of())));
    }

    /** L'identité {@code id} avec ses claims, si elle existe. */
    public Optional<IdentityDTO> findById(String id) {
        List<IdentityClaimDTO> claims = jdbc.query(
                "SELECT * FROM identity_claim WHERE identity_id = ? ORDER BY name", claimMapper, id);
        return jdbc.query("SELECT * FROM identity WHERE id = ?", identityMapper(ignored -> claims), id)
                .stream().findFirst();
    }

    public long count() {
        Long count = jdbc.queryForObject("SELECT COUNT(*) FROM identity", Long.class);
        return count == null ? 0 : count;
    }

    /** Insère l'identité et ses claims dans une même transaction. */
    @Transactional
    public void insert(IdentityDTO identity) {
        log.debug("INSERT identity {}", identity.id());
        jdbc.update("INSERT INTO identity (id, family_name, given_name, birth_date, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                identity.id(), identity.familyName(), identity.givenName(), identity.birthDate().toString(),
                identity.createdAt().toString(), identity.updatedAt().toString());
        identity.claims().forEach(c -> insertClaim(identity.id(), c));
    }

    /** @return {@code false} si l'identité n'existe pas */
    public boolean update(String id, String familyName, String givenName, LocalDate birthDate, Instant now) {
        log.debug("UPDATE identity {}", id);
        return jdbc.update("UPDATE identity SET family_name = ?, given_name = ?, birth_date = ?, updated_at = ? WHERE id = ?",
                familyName, givenName, birthDate.toString(), now.toString(), id) == 1;
    }

    /** Supprime l'identité ; ses claims suivent ({@code ON DELETE CASCADE}). */
    public boolean delete(String id) {
        log.debug("DELETE identity {}", id);
        return jdbc.update("DELETE FROM identity WHERE id = ?", id) == 1;
    }

    public void insertClaim(String identityId, IdentityClaimDTO c) {
        log.debug("INSERT claim {} ({}) of identity {}", c.id(), c.name(), identityId);
        jdbc.update("INSERT INTO identity_claim (id, identity_id, name, type, value, scope) VALUES (?, ?, ?, ?, ?, ?)",
                c.id(), identityId, c.name(), c.type().name(), c.value(), c.scope().name());
    }

    /** @return {@code false} si le claim n'existe pas ou n'appartient pas à l'identité */
    public boolean updateClaim(String identityId, IdentityClaimDTO c) {
        log.debug("UPDATE claim {} ({}) of identity {}", c.id(), c.name(), identityId);
        return jdbc.update("UPDATE identity_claim SET name = ?, type = ?, value = ?, scope = ? WHERE id = ? AND identity_id = ?",
                c.name(), c.type().name(), c.value(), c.scope().name(), c.id(), identityId) == 1;
    }

    /** @return {@code false} si le claim n'existe pas ou n'appartient pas à l'identité */
    public boolean deleteClaim(String identityId, String claimId) {
        log.debug("DELETE claim {} of identity {}", claimId, identityId);
        return jdbc.update("DELETE FROM identity_claim WHERE id = ? AND identity_id = ?", claimId, identityId) == 1;
    }

    /** Met à jour {@code updated_at} après une modification de claim. */
    public void touch(String id, Instant now) {
        jdbc.update("UPDATE identity SET updated_at = ? WHERE id = ?", now.toString(), id);
    }

    /** Ligne {@code identity} → identité, avec les claims fournis par {@code claimsOf} (clé : id de l'identité). */
    private RowMapper<IdentityDTO> identityMapper(java.util.function.Function<String, List<IdentityClaimDTO>> claimsOf) {
        return (rs, n) -> new IdentityDTO(rs.getString("id"), rs.getString("family_name"), rs.getString("given_name"),
                LocalDate.parse(rs.getString("birth_date")), claimsOf.apply(rs.getString("id")),
                Instant.parse(rs.getString("created_at")), Instant.parse(rs.getString("updated_at")));
    }
}
