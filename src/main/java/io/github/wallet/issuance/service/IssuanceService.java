package io.github.wallet.issuance.service;

import io.github.wallet.credentials.service.CredentialStore;
import io.github.wallet.credentials.support.MdocCredential;
import io.github.wallet.credentials.support.ReceivedCredentialReader;
import io.github.wallet.credentials.support.SdJwtVcCredential;
import io.github.wallet.issuance.dto.ReceivedCredentialDTO;
import io.github.wallet.issuance.dto.ReceivedCredentialViewDTO;
import io.github.wallet.issuance.service.dao.ReceivedCredentialDao;
import io.github.wallet.issuance.support.CredentialConfiguration;
import io.github.wallet.issuance.support.CredentialOffer;
import io.github.wallet.issuance.support.CredentialResponse;
import io.github.wallet.issuance.support.IssuanceException;
import io.github.wallet.issuance.support.IssuanceFault;
import io.github.wallet.issuance.support.IssuanceStep;
import io.github.wallet.issuance.support.IssuerMetadata;
import io.github.wallet.issuance.support.OpenId4VciClient;
import io.github.wallet.issuance.support.ProofJwtFactory;
import io.github.wallet.issuance.support.TokenResponse;
import io.github.wallet.presentation.dto.HttpExchangeDTO;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import java.text.ParseException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.multipaz.crypto.EcCurve;
import org.multipaz.crypto.EcPrivateKey;
import org.multipaz.crypto.EcPrivateKeyJvmKt;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import tools.jackson.databind.node.ObjectNode;

/**
 * Réception de credentials par OpenID4VCI 1.0, grant pré-autorisé (le porteur est déjà authentifié chez l'émetteur) :
 * <ol>
 *   <li>{@link #resolve} : lecture de l'offre, metadata de l'émetteur et du serveur d'autorisation ;</li>
 *   <li>{@link #accept} : token, nonce, proof JWT signé par une clé neuve, requête credential, contrôle, stockage,
 *   notification {@code credential_accepted}.</li>
 * </ol>
 * Les credentials reçus sont persistés et ajoutés à ceux de l'identité choisie : ils se présentent ensuite en
 * OpenID4VP comme les credentials de test, signés par leur propre clé.
 */
public class IssuanceService {

    private static final Logger log = LogManager.getLogger(IssuanceService.class);

    /** Formats que le wallet sait lire et présenter. */
    private static final Set<String> FORMATS = Set.of(SdJwtVcCredential.FORMAT, "vc+sd-jwt", MdocCredential.FORMAT);
    /** Défauts qui rendent un {@code invalid_nonce} attendu : pas de nouvel essai. */
    private static final Set<IssuanceFault> NONCE_FAULTS = EnumSet.of(IssuanceFault.PROOF_WRONG_NONCE, IssuanceFault.PROOF_NO_NONCE);

    private final OpenId4VciClient client;
    private final ReceivedCredentialDao dao;
    private final CredentialStore store;
    private final ProofJwtFactory proofs;
    private final ReceivedCredentialReader reader;
    private final Clock clock;

    public IssuanceService(OpenId4VciClient client, ReceivedCredentialDao dao, CredentialStore store,
                           ProofJwtFactory proofs, ReceivedCredentialReader reader, Clock clock) {
        this.client = client;
        this.dao = dao;
        this.store = store;
        this.proofs = proofs;
        this.reader = reader;
        this.clock = clock;
    }

    /** Issue d'une émission : credentials reçus, anomalies, et l'erreur qui l'a interrompue le cas échéant. */
    public record Outcome(List<ReceivedCredentialViewDTO> credentials, List<String> warnings, IssuanceException error) {

        public boolean success() {
            return error == null;
        }
    }

    /** Au démarrage, recharge les credentials reçus ; un credential devenu illisible est ignoré (et tracé). */
    @EventListener(ApplicationReadyEvent.class)
    public void load() {
        int loaded = 0;
        for (ReceivedCredentialDTO c : dao.findAll()) {
            try {
                store.addReceived(c.identityId(), reader.read(c.id(), c.format(), c.credential(), c.credentialIssuer(),
                        multipaz(ECKey.parse(c.holderKey()))).getCredential());
                loaded++;
            } catch (RuntimeException | ParseException e) {
                log.warn("Cannot reload received credential {}: {}", c.id(), e.getMessage());
            }
        }
        log.info("Loaded {} credentials received through OpenID4VCI", loaded);
    }

    // ---------------------------------------------------------------- Offre

    /** Lit l'offre et récupère les metadata ; toute erreur donne une offre {@link PendingOffer.Invalid}. */
    public PendingOffer resolve(String input, String traceId) {
        try {
            CredentialOffer offer = client.offer(input, traceId);
            log.info("[{}] Credential offer from {} for {}", traceId, offer.credentialIssuer(), offer.credentialConfigurationIds());
            IssuerMetadata issuer = client.issuerMetadata(offer.credentialIssuer(), traceId);
            if (!offer.preAuthorized()) {
                throw new IssuanceException(IssuanceStep.OFFER, "only the pre-authorized_code grant is supported"
                        + (offer.authorizationCodeGrant() ? " (this offer uses authorization_code)" : " (no grant in the offer)"));
            }
            var as = client.authorizationServer(authorizationServer(offer, issuer), traceId);
            return new PendingOffer.Valid(traceId, offer, issuer, as);
        } catch (IssuanceException e) {
            log.warn("[{}] Invalid credential offer: {}", traceId, e.getMessage());
            return new PendingOffer.Invalid(traceId, e);
        }
    }

    /** AS du grant, sinon le premier de {@code authorization_servers}, sinon l'émetteur lui-même. */
    private String authorizationServer(CredentialOffer offer, IssuerMetadata issuer) {
        if (offer.authorizationServer() != null) {
            return offer.authorizationServer();
        }
        return issuer.authorizationServers().isEmpty() ? issuer.credentialIssuer() : issuer.authorizationServers().getFirst();
    }

    /** Pourquoi le wallet ne peut pas recevoir cette configuration ; {@code null} s'il le peut. */
    public String unsupportedReason(String configurationId, CredentialConfiguration configuration) {
        if (configuration == null) {
            return "'" + configurationId + "' is not in credential_configurations_supported";
        }
        if (!FORMATS.contains(configuration.format())) {
            return "format '" + configuration.format() + "' is not supported";
        }
        return null;
    }

    // ---------------------------------------------------------------- Émission

    /**
     * Obtient et stocke les credentials de l'offre. Ne lève pas d'{@link IssuanceException} : l'erreur est rendue
     * dans {@link Outcome#error()}, après les credentials déjà reçus.
     *
     * @param txCode     code de transaction, obligatoire si l'offre en exige un
     * @param identityId identité qui reçoit les credentials ; {@code null} = la première
     * @throws IllegalArgumentException identité inconnue ou {@code tx_code} manquant
     */
    public Outcome accept(PendingOffer.Valid pending, String txCode, String identityId, Set<IssuanceFault> faults) {
        String traceId = pending.traceId();
        String identity = identity(identityId);
        CredentialOffer offer = pending.offer();
        if (offer.txCode() != null && (txCode == null || txCode.isBlank())) {
            throw new IllegalArgumentException("this offer requires a tx_code");
        }
        List<ReceivedCredentialViewDTO> received = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        try {
            IssuerMetadata issuer = pending.issuer();
            if (issuer.encryptionRequired()) {
                throw new IssuanceException(IssuanceStep.CREDENTIAL, "the issuer requires credential response encryption (not supported)");
            }
            String code = offer.preAuthorizedCode();
            String tx = offer.txCode() == null ? null : txCode.trim();
            TokenResponse token = client.token(pending.authorizationServer().tokenEndpoint(), code, tx, traceId);
            log.info("[{}] Access token obtained (expires_in {})", traceId, token.expiresIn());
            if (faults.contains(IssuanceFault.TOKEN_REPLAY)) {
                replay(pending, code, tx, warnings);
            }
            String accessToken = faults.contains(IssuanceFault.ACCESS_TOKEN_TAMPERED) ? tamper(token.accessToken()) : token.accessToken();
            String legacyNonce = token.cNonce();

            for (String configurationId : offer.credentialConfigurationIds()) {
                CredentialConfiguration configuration = issuer.configurations().get(configurationId);
                String reason = unsupportedReason(configurationId, configuration);
                if (reason != null) {
                    warnings.add("skipped " + configurationId + ": " + reason);
                    continue;
                }
                if (configuration.proofRequired() && !configuration.proofSigningAlgs().contains("ES256")) {
                    warnings.add(configurationId + ": ES256 is not in proof_signing_alg_values_supported, sent anyway");
                }
                ECKey key = proofs.newHolderKey();
                CredentialResponse response = requestCredential(pending, configuration, token, accessToken, key,
                        legacyNonce, faults);
                for (String credential : response.credentials()) {
                    received.add(store(identity, issuer.credentialIssuer(), configuration, credential, key, traceId));
                }
                notifyAccepted(pending, accessToken, response.notificationId(), warnings);
            }
            if (received.isEmpty() && !offer.credentialConfigurationIds().isEmpty()) {
                throw new IssuanceException(IssuanceStep.CREDENTIAL, "no offered credential can be received by the wallet");
            }
            return new Outcome(received, warnings, null);
        } catch (IssuanceException e) {
            log.warn("[{}] Issuance failed: {}", traceId, e.getMessage());
            return new Outcome(received, warnings, e);
        }
    }

    /** Identité qui reçoit les credentials. */
    private String identity(String identityId) {
        List<String> ids = store.identityIds();
        if (identityId == null || identityId.isBlank()) {
            if (ids.isEmpty()) {
                throw new IllegalArgumentException("the wallet has no identity to attach the credential to");
            }
            return ids.getFirst();
        }
        if (!ids.contains(identityId)) {
            throw new IllegalArgumentException("unknown identity " + identityId);
        }
        return identityId;
    }

    /**
     * Requête credential avec un proof frais. Sur {@code invalid_nonce}, refait une fois la requête avec un nouveau
     * nonce (sauf défaut de nonce injecté, dont c'est la réponse attendue).
     */
    private CredentialResponse requestCredential(PendingOffer.Valid pending, CredentialConfiguration configuration,
                                                 TokenResponse token, String accessToken, ECKey key, String legacyNonce,
                                                 Set<IssuanceFault> faults) {
        IssuerMetadata issuer = pending.issuer();
        String nonce = issuer.nonceEndpoint() != null ? client.nonce(issuer.nonceEndpoint(), pending.traceId()) : legacyNonce;
        try {
            return client.credential(issuer.credentialEndpoint(), accessToken,
                    credentialRequest(configuration, token, key, issuer.credentialIssuer(), nonce, faults), pending.traceId());
        } catch (IssuanceException e) {
            if (!"invalid_nonce".equals(e.getError()) || issuer.nonceEndpoint() == null
                    || faults.stream().anyMatch(NONCE_FAULTS::contains)) {
                throw e;
            }
            log.info("[{}] invalid_nonce: retrying with a fresh nonce", pending.traceId());
            String fresh = client.nonce(issuer.nonceEndpoint(), pending.traceId());
            return client.credential(issuer.credentialEndpoint(), accessToken,
                    credentialRequest(configuration, token, key, issuer.credentialIssuer(), fresh, faults), pending.traceId());
        }
    }

    /**
     * Corps de la requête credential : {@code credential_identifier} si le token en a fourni (obligatoire alors),
     * sinon {@code credential_configuration_id} ; un proof JWT si l'émetteur lie le credential à une clé.
     */
    private ObjectNode credentialRequest(CredentialConfiguration configuration, TokenResponse token, ECKey key,
                                         String credentialIssuer, String nonce, Set<IssuanceFault> faults) {
        ObjectNode request = client.createObjectNode();
        List<String> identifiers = token.credentialIdentifiers().get(configuration.id());
        if (identifiers != null && !identifiers.isEmpty()) {
            request.put("credential_identifier", identifiers.getFirst());
        } else {
            request.put("credential_configuration_id", configuration.id());
        }
        if (configuration.proofRequired()) {
            request.putObject("proofs").putArray("jwt").add(proofs.proof(key, credentialIssuer, nonce, faults));
        }
        return request;
    }

    /** Lit, contrôle, persiste et ajoute au wallet un credential reçu. */
    private ReceivedCredentialViewDTO store(String identityId, String credentialIssuer, CredentialConfiguration configuration,
                                            String credential, ECKey key, String traceId) {
        String id = identityId + ":vci-" + UUID.randomUUID().toString().substring(0, 8);
        ReceivedCredentialReader.Read read;
        try {
            read = reader.read(id, configuration.format(), credential, credentialIssuer, multipaz(key));
        } catch (IllegalArgumentException e) {
            throw new IssuanceException(IssuanceStep.VALIDATION, e.getMessage(), e);
        }
        List<String> warnings = new ArrayList<>(read.getWarnings());
        if (configuration.type() != null && !configuration.type().equals(read.getCredential().getType())) {
            warnings.add("type '" + read.getCredential().getType() + "' differs from the metadata's '"
                    + configuration.type() + "'");
        }
        ReceivedCredentialDTO row = new ReceivedCredentialDTO(id, identityId, credentialIssuer, configuration.id(),
                read.getCredential().getFormat(), credential, key.toJSONString(), List.copyOf(warnings), clock.instant());
        dao.insert(row);
        store.addReceived(identityId, read.getCredential());
        log.info("[{}] Received {} ({} {}) for identity {}{}", traceId, id, row.format(), read.getCredential().getType(),
                identityId, row.warnings().isEmpty() ? "" : ", warnings: " + row.warnings());
        return view(row, read.getCredential().getType());
    }

    /** {@code credential_accepted} ; un échec n'annule pas l'émission. */
    private void notifyAccepted(PendingOffer.Valid pending, String accessToken, String notificationId, List<String> warnings) {
        String endpoint = pending.issuer().notificationEndpoint();
        if (endpoint == null || notificationId == null) {
            return;
        }
        try {
            client.notify(endpoint, accessToken, notificationId, "credential_accepted", pending.traceId());
        } catch (IssuanceException e) {
            warnings.add("notification failed: " + e.getMessage());
        }
    }

    /** Défaut TOKEN_REPLAY : un émetteur correct refuse un pre-authorized_code déjà utilisé. */
    private void replay(PendingOffer.Valid pending, String code, String txCode, List<String> warnings) {
        try {
            client.token(pending.authorizationServer().tokenEndpoint(), code, txCode, pending.traceId());
            warnings.add("the issuer accepted a replayed pre-authorized_code");
        } catch (IssuanceException e) {
            log.info("[{}] Replayed pre-authorized_code rejected as expected: {}", pending.traceId(), e.getMessage());
        }
    }

    private String tamper(String token) {
        int i = token.length() / 2;
        return token.substring(0, i) + (token.charAt(i) == 'A' ? 'B' : 'A') + token.substring(i + 1);
    }

    /** Clé Nimbus → clé Multipaz, attendue par les credentials du wallet. */
    private EcPrivateKey multipaz(ECKey key) {
        try {
            return EcPrivateKeyJvmKt.toEcPrivateKey(key.toECPrivateKey(), key.toECPublicKey(), EcCurve.P256);
        } catch (JOSEException e) {
            throw new IllegalStateException("invalid holder key", e);
        }
    }

    // ---------------------------------------------------------------- Credentials reçus

    /** Credentials reçus, du plus ancien au plus récent. */
    public List<ReceivedCredentialViewDTO> received() {
        return dao.findAll().stream()
                .map(c -> view(c, store.findById(c.id()).map(w -> w.getType()).orElse(null)))
                .toList();
    }

    /** Supprime un credential reçu ; {@code false} s'il est inconnu. */
    public boolean delete(String id) {
        boolean deleted = dao.delete(id);
        store.removeReceived(id);
        if (deleted) {
            log.info("Deleted received credential {}", id);
        }
        return deleted;
    }

    public List<HttpExchangeDTO> exchanges(String traceId) {
        return client.getExchangeLog().forTrace(traceId);
    }

    public List<HttpExchangeDTO> allExchanges() {
        return client.getExchangeLog().all();
    }

    private ReceivedCredentialViewDTO view(ReceivedCredentialDTO c, String type) {
        return new ReceivedCredentialViewDTO(c.id(), c.identityId(), c.credentialIssuer(), c.configurationId(), c.format(),
                type, c.warnings(), c.receivedAt());
    }
}
