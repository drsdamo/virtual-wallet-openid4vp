package io.github.wallet.presentation.support.openid4vp;

import java.net.URI;

/**
 * Issue de l'envoi d'une réponse au verifier.
 *
 * @param accepted    le verifier a accepté la réponse (HTTP 2xx)
 * @param redirectUri où le verifier veut rediriger le navigateur (direct_post), ou l'URI de réponse complète
 *                    (query/fragment)
 */
public record DispatchResult(boolean accepted, URI redirectUri) {
}
