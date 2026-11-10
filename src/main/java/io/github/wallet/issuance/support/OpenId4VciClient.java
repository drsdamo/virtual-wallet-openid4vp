package io.github.wallet.issuance.support;

import io.github.wallet.presentation.dto.HttpExchangeDTO;
import io.github.wallet.presentation.support.openid4vp.ExchangeLog;

import java.io.IOException;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Client HTTP des endpoints OpenID4VCI 1.0 côté wallet : offre, metadata, token, nonce, credential, notification.
 * <p>
 * Écrit à la main (et non avec la lib EUDI OpenID4VCI) : le flux pré-autorisé tient en quelques requêtes, et le
 * wallet doit pouvoir envoyer des requêtes volontairement fausses ({@link IssuanceFault}) et montrer chaque échange
 * tel quel. Chaque appel est tracé dans {@code io.github.wallet.http.out} et conservé dans un {@link ExchangeLog}.
 * <p>
 * Non géré : DPoP, chiffrement de la réponse credential, metadata signées, émission différée.
 */
public class OpenId4VciClient implements AutoCloseable {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private final JsonMapper json;
    private final ExchangeLog exchanges;
    private final HttpClient http;

    public OpenId4VciClient(JsonMapper json, ExchangeLog exchanges) {
        this.json = json;
        this.exchanges = exchanges;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .proxy(ProxySelector.getDefault())
                .build();
    }

    public ExchangeLog getExchangeLog() {
        return exchanges;
    }

    // ---------------------------------------------------------------- Credential Offer

    /**
     * Lit une Credential Offer : JSON brut, ou URI ({@code openid-credential-offer://}, lien https…) portant
     * {@code credential_offer} (par valeur) ou {@code credential_offer_uri} (par référence, téléchargée ici).
     */
    public CredentialOffer offer(String input, String traceId) {
        String text = input.trim();
        String offerJson;
        if (text.startsWith("{")) {
            offerJson = text;
        } else {
            Map<String, String> query = query(text);
            String byValue = query.get("credential_offer");
            String byReference = query.get("credential_offer_uri");
            if (byValue != null && byReference != null) {
                throw new IssuanceException(IssuanceStep.OFFER, "credential_offer and credential_offer_uri are mutually exclusive");
            }
            if (byValue != null) {
                offerJson = byValue;
            } else if (byReference != null) {
                Response r = send("GET", byReference, Map.of("Accept", "application/json"), null, IssuanceStep.OFFER, traceId);
                offerJson = ok(r, IssuanceStep.OFFER).body();
            } else {
                throw new IssuanceException(IssuanceStep.OFFER, "no credential_offer nor credential_offer_uri parameter");
            }
        }
        JsonNode node = parse(offerJson, IssuanceStep.OFFER);
        String issuer = required(node, "credential_issuer", IssuanceStep.OFFER);
        List<String> ids = strings(node.path("credential_configuration_ids"));
        if (ids.isEmpty()) {
            throw new IssuanceException(IssuanceStep.OFFER, "credential_configuration_ids must be a non-empty array");
        }
        JsonNode grants = node.path("grants");
        JsonNode pre = grants.path(CredentialOffer.PRE_AUTHORIZED_GRANT);
        TxCodeSpec txCode = null;
        if (pre.has("tx_code")) {
            JsonNode tx = pre.path("tx_code");
            txCode = new TxCodeSpec(text(tx, "input_mode"), tx.path("length").isNumber() ? tx.path("length").asInt() : null,
                    text(tx, "description"));
        }
        if (pre.isObject() && text(pre, "pre-authorized_code") == null) {
            throw new IssuanceException(IssuanceStep.OFFER, "pre-authorized_code grant without pre-authorized_code");
        }
        return new CredentialOffer(issuer, ids, text(pre, "pre-authorized_code"), txCode,
                text(pre, "authorization_server"), grants.has("authorization_code"), json.writeValueAsString(node));
    }

    // ---------------------------------------------------------------- Metadata

    /** Metadata de l'émetteur ; {@code credential_issuer} doit être identique à celui de l'offre. */
    public IssuerMetadata issuerMetadata(String credentialIssuer, String traceId) {
        Response r = wellKnown(credentialIssuer, "openid-credential-issuer", IssuanceStep.ISSUER_METADATA, traceId);
        if (r.contentType().startsWith("application/jwt")) {
            throw new IssuanceException(IssuanceStep.ISSUER_METADATA, "signed metadata (application/jwt) are not supported");
        }
        JsonNode node = parse(r.body(), IssuanceStep.ISSUER_METADATA);
        String declared = required(node, "credential_issuer", IssuanceStep.ISSUER_METADATA);
        if (!declared.equals(credentialIssuer)) {
            throw new IssuanceException(IssuanceStep.ISSUER_METADATA,
                    "credential_issuer '" + declared + "' differs from the offer's '" + credentialIssuer + "'");
        }
        Map<String, CredentialConfiguration> configurations = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> e : node.path("credential_configurations_supported").properties()) {
            configurations.put(e.getKey(), configuration(e.getKey(), e.getValue()));
        }
        if (configurations.isEmpty()) {
            throw new IssuanceException(IssuanceStep.ISSUER_METADATA, "credential_configurations_supported is missing or empty");
        }
        return new IssuerMetadata(declared, strings(node.path("authorization_servers")),
                required(node, "credential_endpoint", IssuanceStep.ISSUER_METADATA), text(node, "nonce_endpoint"),
                text(node, "notification_endpoint"),
                node.path("credential_response_encryption").path("encryption_required").asBoolean(false),
                configurations, text(node.path("display").path(0), "name"), r.url());
    }

    private CredentialConfiguration configuration(String id, JsonNode node) {
        String type = text(node, "vct") != null ? text(node, "vct") : text(node, "doctype");
        JsonNode jwtProof = node.path("proof_types_supported").path("jwt");
        List<String> algs = jwtProof.isObject() ? strings(jwtProof.path("proof_signing_alg_values_supported")) : null;
        // credential_metadata.display en 1.0, display à la racine dans les brouillons
        JsonNode display = node.path("credential_metadata").path("display").path(0);
        String name = text(display, "name") != null ? text(display, "name") : text(node.path("display").path(0), "name");
        return new CredentialConfiguration(id, text(node, "format"), type, algs, name);
    }

    /** Metadata OAuth (RFC 8414), à défaut OpenID Connect Discovery. */
    public AuthorizationServerMetadata authorizationServer(String issuer, String traceId) {
        Response r;
        try {
            r = wellKnown(issuer, "oauth-authorization-server", IssuanceStep.AUTHORIZATION_SERVER_METADATA, traceId);
        } catch (IssuanceException e) {
            if (e.getStatus() == null || e.getStatus() != 404) {
                throw e;
            }
            r = ok(send("GET", trimSlash(issuer) + "/.well-known/openid-configuration",
                    Map.of("Accept", "application/json"), null, IssuanceStep.AUTHORIZATION_SERVER_METADATA, traceId),
                    IssuanceStep.AUTHORIZATION_SERVER_METADATA);
        }
        JsonNode node = parse(r.body(), IssuanceStep.AUTHORIZATION_SERVER_METADATA);
        return new AuthorizationServerMetadata(text(node, "issuer"),
                required(node, "token_endpoint", IssuanceStep.AUTHORIZATION_SERVER_METADATA),
                strings(node.path("dpop_signing_alg_values_supported")), r.url());
    }

    /**
     * Document {@code .well-known} d'un identifiant : d'abord la forme normative (suffixe inséré entre l'hôte et le
     * chemin), puis, sur 404 d'un identifiant avec chemin, la forme concaténée encore répandue.
     */
    private Response wellKnown(String id, String suffix, IssuanceStep step, String traceId) {
        URI uri = URI.create(id);
        String path = trimSlash(uri.getRawPath() == null ? "" : uri.getRawPath());
        String standard = uri.getScheme() + "://" + uri.getRawAuthority() + "/.well-known/" + suffix + path;
        Response r = send("GET", standard, Map.of("Accept", "application/json"), null, step, traceId);
        if (r.status() == 404 && !path.isEmpty()) {
            r = send("GET", trimSlash(id) + "/.well-known/" + suffix, Map.of("Accept", "application/json"), null, step, traceId);
        }
        return ok(r, step);
    }

    // ---------------------------------------------------------------- Token, nonce, credential, notification

    /** Échange le {@code pre-authorized_code} (et le {@code tx_code}) contre un access token. */
    public TokenResponse token(String tokenEndpoint, String preAuthorizedCode, String txCode, String traceId) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", CredentialOffer.PRE_AUTHORIZED_GRANT);
        form.put("pre-authorized_code", preAuthorizedCode);
        if (txCode != null) {
            form.put("tx_code", txCode);
        }
        String body = form.entrySet().stream()
                .map(e -> enc(e.getKey()) + "=" + enc(e.getValue())).collect(Collectors.joining("&"));
        Response r = ok(send("POST", tokenEndpoint, Map.of("Content-Type", "application/x-www-form-urlencoded",
                "Accept", "application/json"), body, IssuanceStep.TOKEN, traceId), IssuanceStep.TOKEN);
        JsonNode node = parse(r.body(), IssuanceStep.TOKEN);
        Map<String, List<String>> identifiers = new LinkedHashMap<>();
        for (JsonNode detail : node.path("authorization_details")) {
            String configurationId = text(detail, "credential_configuration_id");
            if (configurationId != null) {
                identifiers.put(configurationId, strings(detail.path("credential_identifiers")));
            }
        }
        return new TokenResponse(required(node, "access_token", IssuanceStep.TOKEN), text(node, "token_type"),
                node.path("expires_in").isNumber() ? node.path("expires_in").asLong() : null, text(node, "c_nonce"),
                identifiers);
    }

    /** Nouveau {@code c_nonce} (OpenID4VCI 1.0 §7). */
    public String nonce(String nonceEndpoint, String traceId) {
        Response r = ok(send("POST", nonceEndpoint, Map.of("Accept", "application/json"), "", IssuanceStep.NONCE, traceId),
                IssuanceStep.NONCE);
        return required(parse(r.body(), IssuanceStep.NONCE), "c_nonce", IssuanceStep.NONCE);
    }

    /**
     * Requête credential. Une erreur de l'émetteur (dont {@code invalid_nonce}) lève {@link IssuanceException}
     * avec son code ; une réponse différée (HTTP 202, {@code transaction_id}) n'est pas gérée.
     */
    public CredentialResponse credential(String credentialEndpoint, String accessToken, ObjectNode request, String traceId) {
        Response r = send("POST", credentialEndpoint, Map.of("Content-Type", "application/json", "Accept", "application/json",
                "Authorization", "Bearer " + accessToken), json.writeValueAsString(request), IssuanceStep.CREDENTIAL, traceId);
        if (r.status() == 202) {
            throw new IssuanceException(IssuanceStep.CREDENTIAL, "deferred issuance (HTTP 202, transaction_id) is not supported");
        }
        JsonNode node = parse(ok(r, IssuanceStep.CREDENTIAL).body(), IssuanceStep.CREDENTIAL);
        if (node.has("transaction_id")) {
            throw new IssuanceException(IssuanceStep.CREDENTIAL, "deferred issuance (transaction_id) is not supported");
        }
        List<String> credentials = new ArrayList<>();
        for (JsonNode c : node.path("credentials")) {
            JsonNode value = c.path("credential");
            if (!value.isString()) {
                throw new IssuanceException(IssuanceStep.CREDENTIAL, "only string credentials (SD-JWT, mdoc) are supported");
            }
            credentials.add(value.stringValue());
        }
        // Brouillons antérieurs à 1.0 : un seul credential, au premier niveau
        if (credentials.isEmpty() && node.path("credential").isString()) {
            credentials.add(node.path("credential").stringValue());
        }
        if (credentials.isEmpty()) {
            throw new IssuanceException(IssuanceStep.CREDENTIAL, "no credentials in the response");
        }
        return new CredentialResponse(credentials, text(node, "notification_id"));
    }

    /** Notifie l'émetteur ({@code credential_accepted}, {@code credential_deleted}…). */
    public void notify(String notificationEndpoint, String accessToken, String notificationId, String event, String traceId) {
        ObjectNode body = json.createObjectNode().put("notification_id", notificationId).put("event", event);
        ok(send("POST", notificationEndpoint, Map.of("Content-Type", "application/json", "Authorization", "Bearer " + accessToken),
                json.writeValueAsString(body), IssuanceStep.NOTIFICATION, traceId), IssuanceStep.NOTIFICATION);
    }

    public ObjectNode createObjectNode() {
        return json.createObjectNode();
    }

    // ---------------------------------------------------------------- HTTP

    /** Réponse HTTP lue en entier. */
    private record Response(String url, int status, String contentType, String body) {
    }

    /** Statut 2xx, sinon erreur avec le code OAuth de la réponse s'il y en a un. */
    private Response ok(Response r, IssuanceStep step) {
        if (r.status() >= 200 && r.status() < 300) {
            return r;
        }
        String error = null;
        String description = null;
        try {
            JsonNode node = json.readTree(r.body());
            error = text(node, "error");
            description = text(node, "error_description");
        } catch (JacksonException ignored) {
            // corps non JSON : seul le statut est rapporté
        }
        String message = "HTTP " + r.status() + " from " + r.url() + (error == null ? "" : ": " + error)
                + (description == null ? "" : " (" + description + ")");
        throw new IssuanceException(step, message, r.status(), error, description, null);
    }

    /** Envoie la requête et l'enregistre dans le journal, réponse ou échec réseau compris. */
    private Response send(String method, String url, Map<String, String> headers, String body, IssuanceStep step,
                          String traceId) {
        long start = System.nanoTime();
        Map<String, List<String>> requestHeaders = headers.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> List.of(e.getValue()), (a, b) -> a, LinkedHashMap::new));
        HttpRequest request;
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).timeout(TIMEOUT)
                    .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                            : HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            headers.forEach(builder::header);
            request = builder.build();
        } catch (IllegalArgumentException e) {
            throw new IssuanceException(step, "invalid URL " + url, e);
        }
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            exchanges.add(new HttpExchangeDTO(traceId, Instant.now(), method, url, requestHeaders, body,
                    response.statusCode(), response.headers().map(), response.body(), elapsed(start), null));
            return new Response(url, response.statusCode(),
                    response.headers().firstValue("Content-Type").orElse(""), response.body());
        } catch (IOException e) {
            exchanges.add(new HttpExchangeDTO(traceId, Instant.now(), method, url, requestHeaders, body, null, Map.of(),
                    null, elapsed(start), e.toString()));
            throw new IssuanceException(step, method + " " + url + " failed: " + e, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IssuanceException(step, method + " " + url + " interrupted", e);
        }
    }

    private long elapsed(long start) {
        return (System.nanoTime() - start) / 1_000_000;
    }

    @Override
    public void close() {
        http.close();
    }

    // ---------------------------------------------------------------- JSON et URL

    private JsonNode parse(String body, IssuanceStep step) {
        try {
            JsonNode node = json.readTree(body);
            if (node == null || !node.isObject()) {
                throw new IssuanceException(step, "expected a JSON object");
            }
            return node;
        } catch (JacksonException e) {
            throw new IssuanceException(step, "invalid JSON: " + e.getOriginalMessage(), e);
        }
    }

    /** Valeur texte d'un champ, {@code null} s'il est absent ou n'est pas une chaîne. */
    private String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isString() ? value.stringValue() : null;
    }

    private String required(JsonNode node, String field, IssuanceStep step) {
        String value = text(node, field);
        if (value == null || value.isBlank()) {
            throw new IssuanceException(step, field + " is missing");
        }
        return value;
    }

    private List<String> strings(JsonNode array) {
        List<String> values = new ArrayList<>();
        for (JsonNode n : array) {
            if (n.isString()) {
                values.add(n.stringValue());
            }
        }
        return values;
    }

    /** Paramètres de la query d'une URI, décodés. Le schéma n'est pas contrôlé : il varie selon les émetteurs. */
    private Map<String, String> query(String uri) {
        int q = uri.indexOf('?');
        if (q < 0) {
            throw new IssuanceException(IssuanceStep.OFFER, "not a credential offer: expected JSON or an URI with a query");
        }
        Map<String, String> params = new LinkedHashMap<>();
        for (String pair : uri.substring(q + 1).split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                params.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return params;
    }

    private String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private String trimSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }
}
