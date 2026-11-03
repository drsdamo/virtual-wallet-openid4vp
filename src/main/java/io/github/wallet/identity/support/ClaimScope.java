package io.github.wallet.identity.support;

/** Credentials auxquels un claim additionnel est ajouté. */
public enum ClaimScope {
    /** PID SD-JWT VC et PID mdoc. */
    ALL,
    /** PID SD-JWT VC seulement. Les noms pointés ({@code address.locality}) deviennent des objets imbriqués, divulgables séparément. */
    SD_JWT,
    /** PID mdoc seulement (namespace {@code eu.europa.ec.eudi.pid.1}). */
    MDOC
}
