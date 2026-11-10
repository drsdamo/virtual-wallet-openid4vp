package io.github.wallet.issuance.service.dao;

import io.github.wallet.issuance.dto.ReceivedCredentialDTO;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

/**
 * Accès SQLite à la table {@code received_credential}, via {@link JdbcTemplate}. La suppression d'une identité
 * supprime ses credentials reçus ({@code ON DELETE CASCADE}).
 */
public class ReceivedCredentialDao {

    private static final Logger log = LogManager.getLogger(ReceivedCredentialDao.class);

    private final JdbcTemplate jdbc;

    private final RowMapper<ReceivedCredentialDTO> mapper = (rs, n) -> new ReceivedCredentialDTO(
            rs.getString("id"), rs.getString("identity_id"), rs.getString("credential_issuer"),
            rs.getString("configuration_id"), rs.getString("format"), rs.getString("credential"),
            rs.getString("holder_key"), warnings(rs.getString("warnings")), Instant.parse(rs.getString("received_at")));

    public ReceivedCredentialDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Tous les credentials reçus, du plus ancien au plus récent. */
    public List<ReceivedCredentialDTO> findAll() {
        return jdbc.query("SELECT * FROM received_credential ORDER BY received_at", mapper);
    }

    public void insert(ReceivedCredentialDTO c) {
        jdbc.update("""
                INSERT INTO received_credential (id, identity_id, credential_issuer, configuration_id, format,
                                                 credential, holder_key, warnings, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                c.id(), c.identityId(), c.credentialIssuer(), c.configurationId(), c.format(), c.credential(),
                c.holderKey(), String.join("\n", c.warnings()), c.receivedAt().toString());
        log.debug("Inserted received credential {} ({} from {})", c.id(), c.configurationId(), c.credentialIssuer());
    }

    /** {@code false} si le credential n'existe pas. */
    public boolean delete(String id) {
        return jdbc.update("DELETE FROM received_credential WHERE id = ?", id) > 0;
    }

    private List<String> warnings(String text) {
        return text == null || text.isEmpty() ? List.of() : Arrays.asList(text.split("\n"));
    }
}
