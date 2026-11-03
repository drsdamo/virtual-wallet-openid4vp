package io.github.wallet.presentation.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Appel HTTP du wallet vers un verifier, tel que journalisé par l'ExchangeLog.
 * {@code status} est {@code null} et {@code error} renseigné quand l'appel a échoué (réseau, TLS…).
 */
public record HttpExchangeDTO(String traceId, Instant timestamp, String method, String url,
                              Map<String, List<String>> requestHeaders, String requestBody, Integer status,
                              Map<String, List<String>> responseHeaders, String responseBody, long durationMs,
                              String error) {
}
