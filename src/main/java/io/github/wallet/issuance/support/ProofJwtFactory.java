package io.github.wallet.issuance.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.Set;

/**
 * Clés du porteur et proof JWT de possession de clé (OpenID4VCI 1.0 §8.2.1.1 et annexe F.1).
 * <pre>
 * header  { "typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": &lt;clé publique&gt; }
 * payload { "aud": &lt;credential_issuer&gt;, "iat": …, "nonce": &lt;c_nonce&gt; }
 * </pre>
 * {@code iss} est omis : le grant pré-autorisé est anonyme (pas de {@code client_id}).
 */
public class ProofJwtFactory {

    public static final JOSEObjectType PROOF_TYPE = new JOSEObjectType("openid4vci-proof+jwt");

    private final Clock clock;

    public ProofJwtFactory(Clock clock) {
        this.clock = clock;
    }

    /** Nouvelle clé EC P-256, une par credential : deux credentials ne sont pas corrélables par leur clé. */
    public ECKey newHolderKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("cannot generate a P-256 key", e);
        }
    }

    /**
     * Proof JWT signé par {@code holderKey}, avec les {@code faults} demandés.
     *
     * @param nonce {@code c_nonce} de l'émetteur, {@code null} s'il n'en fournit pas
     */
    public String proof(ECKey holderKey, String credentialIssuer, String nonce, Set<IssuanceFault> faults) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(faults.contains(IssuanceFault.PROOF_WRONG_TYP) ? JOSEObjectType.JWT : PROOF_TYPE)
                    .jwk(holderKey.toPublicJWK())
                    .build();
            Date iat = Date.from(clock.instant().minus(faults.contains(IssuanceFault.PROOF_STALE) ? Duration.ofDays(1) : Duration.ZERO));
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .audience(faults.contains(IssuanceFault.PROOF_WRONG_AUDIENCE) ? "https://not-the-issuer.example" : credentialIssuer)
                    .issueTime(iat);
            if (nonce != null && !faults.contains(IssuanceFault.PROOF_NO_NONCE)) {
                claims.claim("nonce", faults.contains(IssuanceFault.PROOF_WRONG_NONCE) ? nonce + "-tampered" : nonce);
            }
            ECKey signingKey = faults.contains(IssuanceFault.PROOF_KEY_MISMATCH) ? newHolderKey() : holderKey;
            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(new ECDSASigner(signingKey));
            String serialized = jwt.serialize();
            return faults.contains(IssuanceFault.PROOF_BAD_SIGNATURE) ? flipSignature(serialized) : serialized;
        } catch (JOSEException e) {
            throw new IllegalStateException("cannot sign the proof JWT", e);
        }
    }

    /** Change un caractère au milieu de la signature, qui reste du base64url valide. */
    private String flipSignature(String jws) {
        int dot = jws.lastIndexOf('.');
        int i = dot + (jws.length() - dot) / 2;
        char c = jws.charAt(i) == 'A' ? 'B' : 'A';
        return jws.substring(0, i) + c + jws.substring(i + 1);
    }
}
