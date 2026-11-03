package io.github.wallet.credentials.support;

import com.nimbusds.jwt.SignedJWT;
import eu.europa.ec.eudi.sdjwt.SdJwt;
import java.util.Map;

/** Credential SD-JWT VC. Classe à getters (et non record) pour l'accès par propriété depuis Kotlin. */
public final class SdJwtVcCredential implements WalletCredential {

    public static final String FORMAT = "dc+sd-jwt";

    private final String id;
    private final String type;
    private final SdJwt<SignedJWT> sdJwt;
    private final String serialized;
    private final Map<String, Object> claims;

    /**
     * @param sdJwt      SD-JWT émis avec toutes ses disclosures, nécessaire pour construire une présentation
     * @param serialized sérialisation compacte {@code <jwt>~<disclosure>~...~}
     */
    public SdJwtVcCredential(String id, String type, SdJwt<SignedJWT> sdJwt, String serialized, Map<String, Object> claims) {
        this.id = id;
        this.type = type;
        this.sdJwt = sdJwt;
        this.serialized = serialized;
        this.claims = claims;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public Map<String, Object> getClaims() {
        return claims;
    }

    public SdJwt<SignedJWT> getSdJwt() {
        return sdJwt;
    }

    public String getSerialized() {
        return serialized;
    }
}
