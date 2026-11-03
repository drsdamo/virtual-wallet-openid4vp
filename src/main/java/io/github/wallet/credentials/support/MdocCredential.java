package io.github.wallet.credentials.support;

import java.util.Map;
import org.multipaz.cose.CoseSign1;
import org.multipaz.mdoc.issuersigned.IssuerNamespaces;

/** Credential mdoc (ISO 18013-5) : issuerAuth signé et éléments par namespace. */
public final class MdocCredential implements WalletCredential {

    public static final String FORMAT = "mso_mdoc";

    private final String id;
    private final String type;
    private final CoseSign1 issuerAuth;
    private final IssuerNamespaces issuerNamespaces;
    private final Map<String, Object> claims;

    /** @param claims namespace → élément → valeur */
    public MdocCredential(String id, String type, CoseSign1 issuerAuth, IssuerNamespaces issuerNamespaces,
                          Map<String, Object> claims) {
        this.id = id;
        this.type = type;
        this.issuerAuth = issuerAuth;
        this.issuerNamespaces = issuerNamespaces;
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

    /** COSE_Sign1 de l'émetteur sur le MSO. */
    public CoseSign1 getIssuerAuth() {
        return issuerAuth;
    }

    public IssuerNamespaces getIssuerNamespaces() {
        return issuerNamespaces;
    }
}
