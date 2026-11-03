package io.github.wallet.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

/**
 * Trace les requêtes HTTP entrantes dans la catégorie {@code io.github.wallet.http.in}.
 * <ul>
 *   <li>INFO : méthode, URI, statut et durée des appels {@code /api} ;</li>
 *   <li>DEBUG : en plus, en-têtes et corps (tronqués à 8 Ko), et les autres chemins (UI statique, actuator).</li>
 * </ul>
 * Chaque requête reçoit un {@code requestId} dans le contexte Log4j ({@link ThreadContext}), repris par le motif
 * de log : toutes les lignes d'une même requête sont ainsi corrélées.
 */
class HttpTraceFilter extends OncePerRequestFilter {

    private static final Logger log = LogManager.getLogger("io.github.wallet.http.in");
    private static final int MAX_BODY = 8 * 1024;

    /**
     * Enveloppe requête et réponse dans des wrappers qui gardent une copie du corps, puis trace l'appel une fois
     * la chaîne terminée. Sans log actif, la requête passe sans enveloppe : aucun surcoût.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        boolean api = request.getRequestURI().startsWith("/api");
        if (!log.isDebugEnabled() && !(api && log.isInfoEnabled())) {
            chain.doFilter(request, response);
            return;
        }
        var req = new ContentCachingRequestWrapper(request, MAX_BODY);
        var res = new ContentCachingResponseWrapper(response);
        String uri = request.getRequestURI() + (request.getQueryString() == null ? "" : "?" + request.getQueryString());
        ThreadContext.put("requestId", UUID.randomUUID().toString().substring(0, 8));
        long start = System.nanoTime();
        try {
            chain.doFilter(req, res);
        } finally {
            long ms = (System.nanoTime() - start) / 1_000_000;
            if (api) {
                log.info("IN {} {} -> {} ({} ms)", request.getMethod(), uri, res.getStatus(), ms);
            } else {
                log.debug("IN {} {} -> {} ({} ms)", request.getMethod(), uri, res.getStatus(), ms);
            }
            if (log.isDebugEnabled()) {
                log.debug("IN request headers={} body={}", headers(request), body(req.getContentAsByteArray()));
                log.debug("IN response headers={} body={}", responseHeaders(res), body(res.getContentAsByteArray()));
            }
            // Le wrapper a retenu le corps : il faut le recopier dans la vraie réponse.
            res.copyBodyToResponse();
            ThreadContext.remove("requestId");
        }
    }

    /** En-têtes de la requête ; les valeurs multiples sont jointes par une virgule. */
    private Map<String, String> headers(HttpServletRequest request) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (String name : Collections.list(request.getHeaderNames())) {
            headers.put(name, String.join(", ", Collections.list(request.getHeaders(name))));
        }
        return headers;
    }

    /** En-têtes de la réponse. */
    private Map<String, String> responseHeaders(HttpServletResponse response) {
        Map<String, String> headers = new LinkedHashMap<>();
        response.getHeaderNames().forEach(name -> headers.put(name, String.join(", ", response.getHeaders(name))));
        return headers;
    }

    /** Corps décodé en UTF-8, tronqué à {@link #MAX_BODY} octets. */
    private String body(byte[] bytes) {
        if (bytes.length == 0) {
            return "";
        }
        int n = Math.min(bytes.length, MAX_BODY);
        String text = new String(bytes, 0, n, StandardCharsets.UTF_8);
        return bytes.length > MAX_BODY ? text + "... (" + bytes.length + " bytes)" : text;
    }
}
