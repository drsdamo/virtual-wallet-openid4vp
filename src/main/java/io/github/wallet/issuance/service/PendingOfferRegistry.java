package io.github.wallet.issuance.service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * Offres reçues, en attente de la décision du porteur (en mémoire, perdues au redémarrage). Une offre en sort quand
 * le porteur l'accepte ou l'ignore : un {@code pre-authorized_code} ne sert qu'une fois.
 */
public class PendingOfferRegistry {

    /** Offre en attente et date de réception. */
    public record Waiting(PendingOffer offer, Instant receivedAt) {
    }

    private final Clock clock;
    /** Ordre de réception conservé : la plus ancienne offre s'affiche en premier. */
    private final Map<String, Waiting> waiting = new LinkedHashMap<>();

    public PendingOfferRegistry(Clock clock) {
        this.clock = clock;
    }

    public synchronized Waiting add(PendingOffer offer) {
        Waiting w = new Waiting(offer, clock.instant());
        waiting.put(offer.traceId(), w);
        return w;
    }

    public synchronized List<Waiting> all() {
        return new ArrayList<>(waiting.values());
    }

    public synchronized Optional<Waiting> get(String id) {
        return Optional.ofNullable(waiting.get(id));
    }

    /**
     * Retire l'offre si elle est valide.
     *
     * @throws NoSuchElementException offre inconnue ou déjà traitée
     * @throws IllegalStateException  offre invalide, laissée en attente
     */
    public synchronized PendingOffer.Valid take(String id) {
        Waiting w = waiting.get(id);
        if (w == null) {
            throw new NoSuchElementException("unknown or already processed offer " + id);
        }
        if (!(w.offer() instanceof PendingOffer.Valid valid)) {
            throw new IllegalStateException("offer " + id + " is invalid and cannot be accepted");
        }
        waiting.remove(id);
        return valid;
    }

    /** Ignore une offre ; {@code false} si elle n'était pas en attente. */
    public synchronized boolean remove(String id) {
        return waiting.remove(id) != null;
    }
}
