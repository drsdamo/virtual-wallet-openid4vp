package io.github.wallet.credentials.service;

import io.github.wallet.credentials.support.WalletCredential;
import io.github.wallet.identity.dto.IdentityDTO;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Credentials du wallet en mémoire, rangés par identité.
 * <p>
 * Ils ne sont pas persistés : ils sont (ré)émis à partir des identités en base et des clés au démarrage, puis
 * après chaque modification d'une identité. Thread-safe : la map est synchronisée.
 */
public class CredentialStore {

    private final TestCredentialIssuer issuer;
    /** Ordre d'insertion conservé : la première identité est celle proposée par défaut. */
    private final Map<String, List<WalletCredential>> byIdentity = Collections.synchronizedMap(new LinkedHashMap<>());

    public CredentialStore(TestCredentialIssuer issuer) {
        this.issuer = issuer;
    }

    /** Émet (ou réémet) les credentials de l'identité, en remplaçant les précédents. */
    public void issue(IdentityDTO identity) {
        byIdentity.put(identity.id(), List.copyOf(issuer.issueFor(identity)));
    }

    /** Oublie les credentials d'une identité supprimée. */
    public void remove(String identityId) {
        byIdentity.remove(identityId);
    }

    /** Tous les credentials, toutes identités confondues. */
    public List<WalletCredential> all() {
        synchronized (byIdentity) {
            return byIdentity.values().stream().flatMap(List::stream).toList();
        }
    }

    /** Identifiants des identités, dans l'ordre d'émission. */
    public List<String> identityIds() {
        synchronized (byIdentity) {
            return new ArrayList<>(byIdentity.keySet());
        }
    }

    /** Credentials d'une identité ; liste vide si elle est inconnue. */
    public List<WalletCredential> forIdentity(String identityId) {
        return byIdentity.getOrDefault(identityId, List.of());
    }

    /** Credential par identifiant ({@code <identityId>:<type>}). */
    public Optional<WalletCredential> findById(String id) {
        return all().stream().filter(c -> c.getId().equals(id)).findFirst();
    }
}
