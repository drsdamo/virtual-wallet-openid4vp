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
 * Credentials du wallet en mémoire, rangés par identité. Deux origines :
 * <ul>
 *   <li>les credentials de test, non persistés : (ré)émis à partir des identités en base et des clés au démarrage,
 *   puis après chaque modification d'une identité ;</li>
 *   <li>les credentials reçus d'un émetteur par OpenID4VCI, persistés par le domaine issuance et rechargés au
 *   démarrage. Une réémission des credentials de test ne les touche pas.</li>
 * </ul>
 * Thread-safe : les maps sont synchronisées.
 */
public class CredentialStore {

    private final TestCredentialIssuer issuer;
    /** Ordre d'insertion conservé : la première identité est celle proposée par défaut. */
    private final Map<String, List<WalletCredential>> byIdentity = Collections.synchronizedMap(new LinkedHashMap<>());
    /** Credentials reçus par OpenID4VCI, par identité, dans l'ordre de réception. */
    private final Map<String, List<WalletCredential>> receivedByIdentity = Collections.synchronizedMap(new LinkedHashMap<>());

    public CredentialStore(TestCredentialIssuer issuer) {
        this.issuer = issuer;
    }

    /** Émet (ou réémet) les credentials de l'identité, en remplaçant les précédents. */
    public void issue(IdentityDTO identity) {
        byIdentity.put(identity.id(), List.copyOf(issuer.issueFor(identity)));
    }

    /** Oublie tous les credentials (de test et reçus) d'une identité supprimée. */
    public void remove(String identityId) {
        byIdentity.remove(identityId);
        receivedByIdentity.remove(identityId);
    }

    /** Ajoute un credential reçu par OpenID4VCI aux credentials de l'identité. */
    public void addReceived(String identityId, WalletCredential credential) {
        synchronized (receivedByIdentity) {
            List<WalletCredential> list = new ArrayList<>(receivedByIdentity.getOrDefault(identityId, List.of()));
            list.add(credential);
            receivedByIdentity.put(identityId, List.copyOf(list));
        }
    }

    /** Retire un credential reçu ; {@code false} s'il est inconnu. */
    public boolean removeReceived(String credentialId) {
        synchronized (receivedByIdentity) {
            for (Map.Entry<String, List<WalletCredential>> e : receivedByIdentity.entrySet()) {
                List<WalletCredential> kept = e.getValue().stream().filter(c -> !c.getId().equals(credentialId)).toList();
                if (kept.size() != e.getValue().size()) {
                    e.setValue(kept);
                    return true;
                }
            }
            return false;
        }
    }

    /** Tous les credentials, toutes identités confondues. */
    public List<WalletCredential> all() {
        return identityIds().stream().flatMap(id -> forIdentity(id).stream()).toList();
    }

    /** Identifiants des identités, dans l'ordre d'émission. */
    public List<String> identityIds() {
        synchronized (byIdentity) {
            return new ArrayList<>(byIdentity.keySet());
        }
    }

    /** Credentials d'une identité, ceux de test d'abord ; liste vide si elle est inconnue. */
    public List<WalletCredential> forIdentity(String identityId) {
        List<WalletCredential> all = new ArrayList<>(byIdentity.getOrDefault(identityId, List.of()));
        all.addAll(receivedByIdentity.getOrDefault(identityId, List.of()));
        return List.copyOf(all);
    }

    /** Credential par identifiant ({@code <identityId>:<suffixe>}). */
    public Optional<WalletCredential> findById(String id) {
        return all().stream().filter(c -> c.getId().equals(id)).findFirst();
    }
}
