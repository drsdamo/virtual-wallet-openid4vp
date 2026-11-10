package io.github.wallet.issuance.web;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Émetteur OpenID4VCI minimal pour les tests, sur le modèle de l'animation : grant pré-autorisé avec tx_code,
 * nonce endpoint, proof JWT vérifié, SD-JWT VC « compte » ({@code account_id}) lié à la clé du proof.
 * <p>
 * {@code @TestConfiguration} : exclu du scan des autres tests, importé explicitement.
 */
@TestConfiguration(proxyBeanMethods = false)
@RestController
class TestIssuer {

    static final String CONFIGURATION = "compte_wallet";
    static final String TX_CODE = "1234";
    static final String ACCOUNT_ID = "wlt_8Kq2vXr4Tn";

    private final JsonMapper json = JsonMapper.shared();
    private final ECKey signingKey = generate();
    private final SecureRandom random = new SecureRandom();

    /** pre-authorized_code encore utilisables. */
    final Set<String> codes = ConcurrentHashMap.newKeySet();
    final Set<String> tokens = ConcurrentHashMap.newKeySet();
    final Set<String> nonces = ConcurrentHashMap.newKeySet();
    final List<String> notifications = new CopyOnWriteArrayList<>();

    /** Nouvelle offre par valeur, avec tx_code. */
    String newOffer() {
        String code = UUID.randomUUID().toString();
        codes.add(code);
        return """
                {"credential_issuer":"%s","credential_configuration_ids":["%s"],
                 "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"%s",
                   "tx_code":{"input_mode":"numeric","length":4,"description":"Code reçu par SMS"}}}}"""
                .formatted(base(), CONFIGURATION, code);
    }

    /** URL de l'émetteur, connue une fois le port du serveur de test attribué. */
    private volatile String base;

    void start(int port) {
        base = "http://localhost:" + port + "/test-issuer";
    }

    String base() {
        return base;
    }

    String vct() {
        return base() + "/vct/compte";
    }

    @GetMapping("/.well-known/openid-credential-issuer/test-issuer")
    Map<String, Object> issuerMetadata() {
        return Map.of(
                "credential_issuer", base(),
                "credential_endpoint", base() + "/credential",
                "nonce_endpoint", base() + "/nonce",
                "notification_endpoint", base() + "/notification",
                "credential_configurations_supported", Map.of(CONFIGURATION, Map.of(
                        "format", "dc+sd-jwt",
                        "vct", vct(),
                        "cryptographic_binding_methods_supported", List.of("jwk"),
                        "proof_types_supported", Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))),
                        "credential_metadata", Map.of("display", List.of(Map.of("name", "Compte wallet"))))));
    }

    @GetMapping("/.well-known/oauth-authorization-server/test-issuer")
    Map<String, Object> asMetadata() {
        return Map.of("issuer", base(), "token_endpoint", base() + "/token");
    }

    @PostMapping("/test-issuer/token")
    ResponseEntity<Map<String, Object>> token(@RequestParam("grant_type") String grantType,
                                              @RequestParam("pre-authorized_code") String code,
                                              @RequestParam(name = "tx_code", required = false) String txCode) {
        if (!"urn:ietf:params:oauth:grant-type:pre-authorized_code".equals(grantType)) {
            return error("unsupported_grant_type");
        }
        if (!TX_CODE.equals(txCode) || !codes.remove(code)) {
            return error("invalid_grant");
        }
        String token = UUID.randomUUID().toString();
        tokens.add(token);
        return ResponseEntity.ok(Map.of("access_token", token, "token_type", "Bearer", "expires_in", 300));
    }

    @PostMapping("/test-issuer/nonce")
    Map<String, Object> nonce() {
        String nonce = UUID.randomUUID().toString();
        nonces.add(nonce);
        return Map.of("c_nonce", nonce);
    }

    @PostMapping("/test-issuer/credential")
    ResponseEntity<Map<String, Object>> credential(@RequestHeader("Authorization") String authorization,
                                                   @RequestBody JsonNode request) throws Exception {
        if (!tokens.contains(authorization.replaceFirst("^Bearer ", ""))) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid_token"));
        }
        if (!CONFIGURATION.equals(request.path("credential_configuration_id").asString(""))) {
            return error("unknown_credential_configuration");
        }
        SignedJWT proof = SignedJWT.parse(request.path("proofs").path("jwt").path(0).asString(""));
        ECKey holder = (ECKey) proof.getHeader().getJWK();
        JWTClaimsSet claims = proof.getJWTClaimsSet();
        boolean valid = new JOSEObjectType("openid4vci-proof+jwt").equals(proof.getHeader().getType())
                && holder != null && proof.verify(new ECDSAVerifier(holder))
                && claims.getAudience().equals(List.of(base()))
                && claims.getIssueTime().toInstant().isAfter(Instant.now().minusSeconds(300));
        if (!valid) {
            return error("invalid_proof");
        }
        if (!nonces.remove(String.valueOf(claims.getClaim("nonce")))) {
            return error("invalid_nonce");
        }
        String notificationId = UUID.randomUUID().toString();
        return ResponseEntity.ok(Map.of("credentials", List.of(Map.of("credential", sdJwt(holder))),
                "notification_id", notificationId));
    }

    @PostMapping("/test-issuer/notification")
    ResponseEntity<Void> notification(@RequestBody JsonNode body) {
        notifications.add(body.path("event").asString(""));
        return ResponseEntity.noContent().build();
    }

    /** SD-JWT VC : account_id divulgable, cnf = clé du proof. Pas de x5c : le wallet signale une signature non vérifiée. */
    private String sdJwt(ECKey holder) throws JOSEException {
        String disclosure = b64(json.writeValueAsBytes(List.of(b64(randomBytes()), "account_id", ACCOUNT_ID)));
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(base())
                .claim("vct", vct())
                .issueTime(new Date())
                .claim("cnf", Map.of("jwk", holder.toPublicJWK().toJSONObject()))
                .claim("_sd", List.of(b64(sha256(disclosure))))
                .claim("_sd_alg", "sha-256")
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dc+sd-jwt")).build(), claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize() + "~" + disclosure + "~";
    }

    private ResponseEntity<Map<String, Object>> error(String code) {
        return ResponseEntity.badRequest().body(Map.of("error", code));
    }

    private byte[] randomBytes() {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private ECKey generate() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Clé {@code cnf.jwk} du SD-JWT présenté. */
    ECKey cnf(String presentation) throws ParseException {
        Map<String, Object> cnf = SignedJWT.parse(presentation.substring(0, presentation.indexOf('~')))
                .getJWTClaimsSet().getJSONObjectClaim("cnf");
        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
        return ECKey.parse(jwk);
    }
}
