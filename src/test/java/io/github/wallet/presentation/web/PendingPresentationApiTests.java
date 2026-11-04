package io.github.wallet.presentation.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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

/** File des présentations en attente de la décision du porteur, telle que l'IHM l'interroge. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "wallet.data-dir=target/test-pending-api")
class PendingPresentationApiTests {

    @LocalServerPort
    int port;

    RestClient http;

    @BeforeEach
    void setUp() {
        http = RestClient.builder().baseUrl("http://localhost:" + port).build();
    }

    /** Requête par valeur non signée ({@code redirect_uri:}) : résolue sans appel réseau. */
    private String demoRequest() {
        String responseUri = "https://verifier.example/response";
        String dcql = """
                {"credentials":[
                  {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]},
                  {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
                   "claims":[{"path":["org.iso.18013.5.1","age_over_18"]}]}]}""";
        return "openid4vp://?client_id=" + enc("redirect_uri:" + responseUri)
                + "&response_type=vp_token&response_mode=direct_post&response_uri=" + enc(responseUri)
                + "&nonce=n-" + System.nanoTime() + "&state=s&dcql_query=" + enc(dcql);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private Map<String, Object> present(String requestUri) {
        return http.post().uri("/api/presentations").contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("requestUri", requestUri)).retrieve().body(new ParameterizedTypeReference<>() { });
    }

    private List<Map<String, Object>> pending() {
        return http.get().uri("/api/presentations/pending").retrieve().body(new ParameterizedTypeReference<>() { });
    }

    @Test
    @SuppressWarnings("unchecked")
    void incomingPresentationWaitsWithRequestedClaimsAndValues() {
        String id = (String) present(demoRequest()).get("id");

        Map<String, Object> waiting = pending().stream().filter(p -> p.get("id").equals(id)).findFirst().orElseThrow();
        assertThat(waiting.get("valid")).isEqualTo(true);
        assertThat(waiting.get("receivedAt")).isNotNull();
        List<Map<String, Object>> queries = (List<Map<String, Object>>) waiting.get("queries");
        Map<String, Object> pid = queries.stream().filter(q -> q.get("queryId").equals("pid")).findFirst().orElseThrow();
        assertThat((List<Map<String, Object>>) pid.get("claims"))
                .singleElement().satisfies(c -> {
                    assertThat(c.get("path")).isEqualTo(List.of("family_name"));
                    assertThat(c.get("value")).isInstanceOf(String.class);
                });
        Map<String, Object> mdl = queries.stream().filter(q -> q.get("queryId").equals("mdl")).findFirst().orElseThrow();
        // les claims lisibles d'un mdoc sont sous forme d'affichage ("true")
        assertThat(String.valueOf(((List<Map<String, Object>>) mdl.get("claims")).getFirst().get("value")))
                .isEqualTo("true");

        Map<String, Object> one = http.get().uri("/api/presentations/" + id).retrieve()
                .body(new ParameterizedTypeReference<>() { });
        assertThat(one.get("id")).isEqualTo(id);

        // ignorée : sort de la file, plus aucune réponse possible
        http.delete().uri("/api/presentations/" + id).retrieve().toBodilessEntity();
        assertThat(pending()).noneMatch(p -> p.get("id").equals(id));
        assertThatThrownBy(() -> http.post().uri("/api/presentations/" + id + "/decline").retrieve().toBodilessEntity())
                .isInstanceOf(HttpClientErrorException.NotFound.class);
        assertThatThrownBy(() -> http.delete().uri("/api/presentations/" + id).retrieve().toBodilessEntity())
                .isInstanceOf(HttpClientErrorException.NotFound.class);
    }

    @Test
    void invalidRequestAlsoWaitsAndCannotBeAccepted() {
        String id = (String) present("openid4vp://?client_id=nope").get("id");

        assertThat(pending()).anySatisfy(p -> {
            assertThat(p.get("id")).isEqualTo(id);
            assertThat(p.get("valid")).isEqualTo(false);
            assertThat(p.get("error")).isNotNull();
        });
        assertThatThrownBy(() -> http.post().uri("/api/presentations/" + id + "/accept")
                .contentType(MediaType.APPLICATION_JSON).body(Map.of()).retrieve().toBodilessEntity())
                .isInstanceOf(HttpClientErrorException.Conflict.class);
        assertThat(pending()).anyMatch(p -> p.get("id").equals(id));
        http.delete().uri("/api/presentations/" + id).retrieve().toBodilessEntity();
    }
}
