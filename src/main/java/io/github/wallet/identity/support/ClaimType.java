package io.github.wallet.identity.support;

import java.math.BigDecimal;
import java.time.LocalDate;

/** Type de la valeur d'un claim additionnel, stockée en texte et convertie à l'émission des credentials. */
public enum ClaimType {
    STRING, NUMBER, BOOLEAN, DATE;

    /**
     * Analyse et normalise {@code raw} (nombre sans zéros inutiles, booléen en minuscules, date ISO).
     *
     * @throws IllegalArgumentException si la valeur ne correspond pas au type
     */
    public String normalise(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("value is required");
        }
        String v = raw.trim();
        try {
            return switch (this) {
                case STRING -> raw; // texte conservé tel quel, espaces compris
                case NUMBER -> new BigDecimal(v).toPlainString();
                case BOOLEAN -> {
                    if (!v.equalsIgnoreCase("true") && !v.equalsIgnoreCase("false")) {
                        throw new IllegalArgumentException("expected true or false");
                    }
                    yield v.toLowerCase();
                }
                case DATE -> LocalDate.parse(v).toString();
            };
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("invalid " + this + " value '" + raw + "': " + e.getMessage(), e);
        }
    }
}
