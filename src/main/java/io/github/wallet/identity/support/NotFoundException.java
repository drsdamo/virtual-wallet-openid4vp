package io.github.wallet.identity.support;

/** Identité ou claim inconnu : traduit en HTTP 404 par le controller. */
public class NotFoundException extends RuntimeException {

    /** @param what ce qui manque, par exemple {@code "identity 42"} */
    public NotFoundException(String what) {
        super(what + " not found");
    }
}
