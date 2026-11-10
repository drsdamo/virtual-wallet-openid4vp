package io.github.wallet.issuance.web;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Scénario de l'animation de bout en bout : offre pré-autorisée (QR), metadata, token avec tx_code, nonce, proof JWT,
 * credential « compte » lié à une clé neuve, puis présentation OpenID4VP de ce credential, signée par cette clé.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "wallet.data-dir=target/test-issuance-api")
@Import(TestIssuer.class)
class IssuanceApiTests {

    private static final ParameterizedTypeReference<Map<String, Object>> MAP = new ParameterizedTypeReference<>() { };

    @LocalServerPort
    int port;

    @Autowired
    TestIssuer issuer;

    RestClient http;

    @BeforeEach
    void setUp() {
        issuer.start(port);
        // pas d'exception sur 4xx/5xx : les tests vérifient les statuts
        http = RestClient.builder().baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> { })
                .build();
    }

    private ResponseEntity<Map<String, Object>> post(String uri, Object body) {
        return http.post().uri(uri).contentType(MediaType.APPLICATION_JSON).body(body).retrieve().toEntity(MAP);
    }

    private String offerUri() {
        return "openid-credential-offer://?credential_offer=" + enc(issuer.newOffer());
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    @Test
    @SuppressWarnings("unchecked")
    void enrolmentThenLoginWithTheReceivedCredential() throws Exception {
        Map<String, Object> offer = post("/api/offers", Map.of("offer", offerUri())).getBody();
        assertThat(offer.get("valid")).isEqualTo(true);
        assertThat(offer.get("credentialIssuer")).isEqualTo(issuer.base());
        assertThat((Map<String, Object>) offer.get("txCode")).containsEntry("length", 4);
        Map<String, Object> offered = ((List<Map<String, Object>>) offer.get("credentials")).getFirst();
        assertThat(offered).containsEntry("configurationId", TestIssuer.CONFIGURATION).containsEntry("supported", true)
                .containsEntry("name", "Compte wallet");

        ResponseEntity<Map<String, Object>> accepted = post("/api/offers/" + offer.get("id") + "/accept",
                Map.of("txCode", TestIssuer.TX_CODE));
        assertThat(accepted.getStatusCode().value()).isEqualTo(200);
        Map<String, Object> credential = ((List<Map<String, Object>>) accepted.getBody().get("credentials")).getFirst();
        assertThat(credential.get("type")).isEqualTo(issuer.vct());
        // l'émetteur de test ne met pas de x5c : seul cet avertissement est attendu (cnf = clé du proof)
        assertThat((List<String>) credential.get("warnings")).singleElement().asString().contains("not verified");
        assertThat(issuer.notifications).contains("credential_accepted");
        List<Map<String, Object>> received = http.get().uri("/api/received-credentials").retrieve()
                .body(new ParameterizedTypeReference<>() { });
        assertThat(received).extracting(c -> c.get("id")).contains(credential.get("id"));
        // les autres tests (et les exécutions précédentes) en ont reçu d'autres : seul celui-ci doit répondre
        received.stream().map(c -> (String) c.get("id")).filter(id -> !id.equals(credential.get("id")))
                .forEach(id -> assertThat(http.delete().uri("/api/received-credentials/" + id).retrieve()
                        .toBodilessEntity().getStatusCode().value()).isEqualTo(204));

        // Connexion : le verifier demande account_id, le wallet présente le credential reçu
        // La lib OpenID4VP exige une response_uri https : le verifier est injoignable, le vp_token envoyé est relu
        // dans le journal des échanges.
        String responseUri = "https://verifier.invalid/response";
        String dcql = """
                {"credentials":[{"id":"compte","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
                  "claims":[{"path":["account_id"]}]}]}""".formatted(issuer.vct());
        String nonce = "n-" + System.nanoTime();
        String request = "openid4vp://?client_id=" + enc("redirect_uri:" + responseUri)
                + "&response_type=vp_token&response_mode=direct_post&response_uri=" + enc(responseUri)
                + "&nonce=" + nonce + "&state=s&dcql_query=" + enc(dcql);
        Map<String, Object> pending = post("/api/presentations", Map.of("requestUri", request)).getBody();
        Map<String, Object> query = ((List<Map<String, Object>>) pending.get("queries")).getFirst();
        assertThat(query.get("credentialId")).isEqualTo(credential.get("id"));
        assertThat(((List<Map<String, Object>>) query.get("claims")).getFirst().get("value")).isEqualTo(TestIssuer.ACCOUNT_ID);

        post("/api/presentations/" + pending.get("id") + "/accept", Map.of());
        List<Map<String, Object>> exchanges = http.get().uri("/api/presentations/" + pending.get("id") + "/exchanges")
                .retrieve().body(new ParameterizedTypeReference<>() { });
        String form = (String) exchanges.getLast().get("requestBody");
        String vpTokenParam = java.util.Arrays.stream(form.split("&")).filter(p -> p.startsWith("vp_token="))
                .map(p -> java.net.URLDecoder.decode(p.substring("vp_token=".length()), StandardCharsets.UTF_8))
                .findFirst().orElseThrow();
        JsonNode vpToken = JsonMapper.shared().readTree(vpTokenParam);
        String presentation = vpToken.path("compte").path(0).asString();
        // KB-JWT signé par la clé enregistrée à l'enrôlement (cnf), avec le nonce du verifier
        SignedJWT kb = SignedJWT.parse(presentation.substring(presentation.lastIndexOf('~') + 1));
        assertThat(kb.verify(new ECDSAVerifier(issuer.cnf(presentation)))).isTrue();
        assertThat(kb.getJWTClaimsSet().getStringClaim("nonce")).isEqualTo(nonce);
    }

    @Test
    void missingTxCodeIsRejectedAndTheOfferStaysPending() {
        String id = (String) post("/api/offers", Map.of("offer", offerUri())).getBody().get("id");

        assertThat(post("/api/offers/" + id + "/accept", Map.of()).getStatusCode().value()).isEqualTo(400);
        assertThat(http.get().uri("/api/offers/" + id).retrieve().toEntity(MAP).getStatusCode().value()).isEqualTo(200);
    }

    @Test
    void wrongTxCodeIsReportedWithTheIssuerError() {
        String id = (String) post("/api/offers", Map.of("offer", offerUri())).getBody().get("id");

        ResponseEntity<Map<String, Object>> r = post("/api/offers/" + id + "/accept", Map.of("txCode", "0000"));
        assertThat(r.getStatusCode().value()).isEqualTo(502);
        assertThat(r.getBody()).containsEntry("step", "TOKEN").containsEntry("oauthError", "invalid_grant")
                .containsEntry("success", false);
        assertThat((List<?>) r.getBody().get("exchanges")).isNotEmpty();
    }

    @Test
    void injectedProofFaultIsRejectedByTheIssuer() {
        String id = (String) post("/api/offers", Map.of("offer", offerUri())).getBody().get("id");

        ResponseEntity<Map<String, Object>> r = post("/api/offers/" + id + "/accept",
                Map.of("txCode", TestIssuer.TX_CODE, "faults", List.of("PROOF_WRONG_NONCE")));
        assertThat(r.getStatusCode().value()).isEqualTo(502);
        assertThat(r.getBody()).containsEntry("step", "CREDENTIAL").containsEntry("oauthError", "invalid_nonce");
    }

    @Test
    @SuppressWarnings("unchecked")
    void replayedPreAuthorizedCodeRejectedByTheIssuerGivesNoWarning() {
        String id = (String) post("/api/offers", Map.of("offer", offerUri())).getBody().get("id");

        ResponseEntity<Map<String, Object>> r = post("/api/offers/" + id + "/accept",
                Map.of("txCode", TestIssuer.TX_CODE, "faults", List.of("TOKEN_REPLAY")));
        assertThat(r.getStatusCode().value()).isEqualTo(200);
        assertThat((List<String>) r.getBody().get("warnings")).isEmpty();
    }

    @Test
    void unreachableIssuerGivesAnInvalidOffer() {
        String offer = """
                {"credential_issuer":"http://localhost:%d/nowhere","credential_configuration_ids":["x"],
                 "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"c"}}}"""
                .formatted(port);

        Map<String, Object> r = post("/api/offers", Map.of("offer", offer)).getBody();
        assertThat(r).containsEntry("valid", false).containsEntry("step", "ISSUER_METADATA");
        assertThat(post("/api/offers/" + r.get("id") + "/accept", Map.of()).getStatusCode().value()).isEqualTo(409);
    }
}
