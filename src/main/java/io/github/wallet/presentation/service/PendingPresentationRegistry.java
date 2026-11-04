package io.github.wallet.presentation.service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * Présentations reçues, en attente de la décision du porteur (en mémoire, perdues au redémarrage).
 * <p>
 * L'IHM interroge cette file pour avertir le porteur ; une présentation en sort quand il y répond ou l'ignore.
 */
public class PendingPresentationRegistry {

    /** Présentation en attente et date de réception. */
    public record Waiting(PendingPresentation presentation, Instant receivedAt) {
    }

    private final Clock clock;
    /** Ordre de réception conservé : la plus ancienne demande s'affiche en premier. */
    private final Map<String, Waiting> waiting = new LinkedHashMap<>();

    public PendingPresentationRegistry(Clock clock) {
        this.clock = clock;
    }

    /** Met une présentation en attente, sous son identifiant de corrélation. */
    public synchronized Waiting add(PendingPresentation presentation) {
        Waiting w = new Waiting(presentation, clock.instant());
        waiting.put(presentation.traceId(), w);
        return w;
    }

    /** Présentations en attente, de la plus ancienne à la plus récente. */
    public synchronized List<Waiting> all() {
        return new ArrayList<>(waiting.values());
    }

    public synchronized Optional<Waiting> get(String id) {
        return Optional.ofNullable(waiting.get(id));
    }

    /**
     * Retire la présentation si elle a le type attendu : une demande n'est répondue qu'une fois.
     *
     * @throws NoSuchElementException présentation inconnue ou déjà répondue
     * @throws IllegalStateException            présentation d'un autre type (valide / invalide), laissée en attente
     */
    public synchronized <T extends PendingPresentation> T take(String id, Class<T> type) {
        Waiting w = waiting.get(id);
        if (w == null) {
            throw new NoSuchElementException("unknown or already answered request " + id);
        }
        if (!type.isInstance(w.presentation())) {
            throw new IllegalStateException("request " + id + " is not " + type.getSimpleName());
        }
        waiting.remove(id);
        return type.cast(w.presentation());
    }

    /** Ignore une présentation sans rien répondre au verifier ; {@code false} si elle n'était pas en attente. */
    public synchronized boolean remove(String id) {
        return waiting.remove(id) != null;
    }
}
