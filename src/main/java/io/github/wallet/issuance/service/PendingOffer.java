package io.github.wallet.issuance.service;

import io.github.wallet.issuance.support.AuthorizationServerMetadata;
import io.github.wallet.issuance.support.CredentialOffer;
import io.github.wallet.issuance.support.IssuanceException;
import io.github.wallet.issuance.support.IssuerMetadata;

/** Credential Offer reçue, en attente de la décision du porteur. */
public sealed interface PendingOffer {

    /** Corrèle les échanges HTTP de cette émission dans le journal. */
    String traceId();

    /** Offre lue et metadata de l'émetteur et du serveur d'autorisation récupérées. */
    record Valid(String traceId, CredentialOffer offer, IssuerMetadata issuer,
                 AuthorizationServerMetadata authorizationServer) implements PendingOffer {
    }

    /** Offre illisible, metadata introuvables ou incohérentes, ou grant non géré. */
    record Invalid(String traceId, IssuanceException error) implements PendingOffer {
    }
}
