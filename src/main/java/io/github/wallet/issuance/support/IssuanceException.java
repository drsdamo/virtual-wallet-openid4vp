package io.github.wallet.issuance.support;

/**
 * Échec d'une étape OpenID4VCI : réponse HTTP en erreur, réponse invalide ou fonctionnalité non gérée.
 * {@code status}, {@code error} et {@code errorDescription} reprennent la réponse de l'émetteur quand il y en a une.
 */
public class IssuanceException extends RuntimeException {

    private final IssuanceStep step;
    private final Integer status;
    private final String error;
    private final String errorDescription;

    public IssuanceException(IssuanceStep step, String message) {
        this(step, message, null, null, null, null);
    }

    public IssuanceException(IssuanceStep step, String message, Throwable cause) {
        this(step, message, null, null, null, cause);
    }

    public IssuanceException(IssuanceStep step, String message, Integer status, String error, String errorDescription,
                             Throwable cause) {
        super(step + ": " + message, cause);
        this.step = step;
        this.status = status;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public IssuanceStep getStep() {
        return step;
    }

    /** Statut HTTP de la réponse en erreur, {@code null} si l'échec n'est pas une réponse HTTP. */
    public Integer getStatus() {
        return status;
    }

    /** Code d'erreur OAuth / OpenID4VCI ({@code invalid_proof}, {@code invalid_grant}…), s'il est fourni. */
    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }
}
