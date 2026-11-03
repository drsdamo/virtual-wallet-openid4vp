package io.github.wallet.presentation.dto;

/**
 * Corps de {@code POST /api/presentations}.
 *
 * @param requestUri requête d'autorisation ({@code openid4vp://...}, {@code haip-vp://...} ou {@code https://...})
 * @param identityId identité à présenter ; optionnelle : à défaut, la première qui répond à toute la requête
 */
public record ResolveRequestDTO(String requestUri, String identityId) {
}
