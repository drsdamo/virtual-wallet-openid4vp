package io.github.wallet.issuance.support;

import java.util.List;

/**
 * Réponse immédiate du credential endpoint (HTTP 200).
 *
 * @param credentials    credentials émis, un par proof
 * @param notificationId à renvoyer au notification endpoint, {@code null} si absent
 */
public record CredentialResponse(List<String> credentials, String notificationId) {
}
