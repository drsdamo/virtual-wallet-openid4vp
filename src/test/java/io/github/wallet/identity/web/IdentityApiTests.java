package io.github.wallet.identity.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/** API identités de bout en bout, sur un port aléatoire et une base SQLite dédiée. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "wallet.data-dir=target/test-identity-api")
class IdentityApiTests {

    @LocalServerPort
    int port;

    RestClient http;

    @BeforeEach
    void setUp() {
        http = RestClient.builder().baseUrl("http://localhost:" + port).build();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> identity(Map<String, Object> view) {
        return (Map<String, Object>) view.get("identity");
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> list(Map<String, Object> view, String key) {
        return (List<Map<String, Object>>) view.get(key);
    }

    private Map<String, Object> send(String method, String path, Object body) {
        var spec = http.method(org.springframework.http.HttpMethod.valueOf(method)).uri(path);
        if (body != null) {
            spec = spec.contentType(MediaType.APPLICATION_JSON).body(body);
        }
        return spec.retrieve().body(new ParameterizedTypeReference<>() { });
    }

    @Test
    void crudOnIdentityAndClaimsReissuesCredentials() {
        // création
        Map<String, Object> created = send("POST", "/api/identities", Map.of(
                "familyName", "DURAND", "givenName", "Léa", "birthDate", "2001-02-03",
                "claims", List.of(Map.of("name", "nationality", "value", "FR", "scope", "ALL"))));
        String id = (String) identity(created).get("id");
        assertThat(list(created, "credentials")).extracting(c -> c.get("id"))
                .containsExactlyInAnyOrder(id + ":pid-sd-jwt", id + ":pid-mdoc", id + ":mdl-mdoc");

        // les nouveaux claims apparaissent dans les credentials émis
        Map<String, Object> claim = send("POST", "/api/identities/" + id + "/claims",
                Map.of("name", "address.locality", "value", "Nantes", "scope", "SD_JWT"));
        String claimId = (String) list(identity(claim), "claims").stream()
                .filter(c -> c.get("name").equals("address.locality")).findFirst().orElseThrow().get("id");
        List<Map<String, Object>> credentials = http.get().uri("/api/credentials").retrieve()
                .body(new ParameterizedTypeReference<>() { });
        Map<String, Object> pid = credentials.stream().filter(c -> c.get("id").equals(id + ":pid-sd-jwt")).findFirst().orElseThrow();
        assertThat(((Map<?, ?>) pid.get("claims")).get("family_name")).isEqualTo("DURAND");
        assertThat(((Map<?, ?>) ((Map<?, ?>) pid.get("claims")).get("address")).get("locality")).isEqualTo("Nantes");
        assertThat(((Map<?, ?>) pid.get("claims")).get("nationality")).isEqualTo("FR");

        // modification de l'identité et d'un claim
        Map<String, Object> updated = send("PUT", "/api/identities/" + id,
                Map.of("familyName", "DURAND-PETIT", "givenName", "Léa", "birthDate", "2001-02-03"));
        assertThat(identity(updated).get("familyName")).isEqualTo("DURAND-PETIT");
        Map<String, Object> claimUpdated = send("PUT", "/api/identities/" + id + "/claims/" + claimId,
                Map.of("name", "address.locality", "value", "Rennes", "scope", "SD_JWT"));
        assertThat(list(identity(claimUpdated), "claims")).extracting(c -> c.get("value")).contains("Rennes");

        // persisté : relu depuis la base
        assertThat(identity(send("GET", "/api/identities/" + id, null)).get("familyName")).isEqualTo("DURAND-PETIT");

        // suppression du claim, puis de l'identité
        Map<String, Object> afterClaimDelete = send("DELETE", "/api/identities/" + id + "/claims/" + claimId, null);
        assertThat(list(identity(afterClaimDelete), "claims")).extracting(c -> c.get("name")).doesNotContain("address.locality");
        http.delete().uri("/api/identities/" + id).retrieve().toBodilessEntity();
        assertThatThrownBy(() -> send("GET", "/api/identities/" + id, null))
                .isInstanceOf(HttpClientErrorException.NotFound.class);
        List<Map<String, Object>> remaining = http.get().uri("/api/credentials").retrieve().body(new ParameterizedTypeReference<>() { });
        assertThat(remaining).noneMatch(c -> ((String) c.get("id")).startsWith(id));
    }

    @Test
    void rejectsInvalidInput() {
        assertThatThrownBy(() -> send("POST", "/api/identities", Map.of("familyName", "X", "givenName", "Y")))
                .isInstanceOf(HttpClientErrorException.BadRequest.class);
        String id = (String) identity(send("POST", "/api/identities",
                Map.of("familyName", "X", "givenName", "Y", "birthDate", "1980-01-01"))).get("id");
        // nom réservé, mauvais type, doublon
        assertThatThrownBy(() -> send("POST", "/api/identities/" + id + "/claims", Map.of("name", "family_name", "value", "Z")))
                .isInstanceOf(HttpClientErrorException.BadRequest.class);
        assertThatThrownBy(() -> send("POST", "/api/identities/" + id + "/claims", Map.of("name", "height", "type", "NUMBER", "value", "tall")))
                .isInstanceOf(HttpClientErrorException.BadRequest.class);
        send("POST", "/api/identities/" + id + "/claims", Map.of("name", "nickname", "value", "Z"));
        assertThatThrownBy(() -> send("POST", "/api/identities/" + id + "/claims", Map.of("name", "nickname", "value", "W", "scope", "MDOC")))
                .isInstanceOf(HttpClientErrorException.BadRequest.class);
    }
}
