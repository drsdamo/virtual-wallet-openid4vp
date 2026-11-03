package io.github.wallet.presentation.support.openid4vp;

import eu.europa.ec.eudi.openid4vp.Resolution;
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject;

/** Résultat de {@link OpenId4VpWalletClient#resolve}. */
public sealed interface WalletResolution {

    /** Requête valide et authentifiée. */
    record Valid(ResolvedRequestObject request) implements WalletResolution {
    }

    /** Requête rejetée par la lib EUDI ; {@link #errorDescription()} dit pourquoi. */
    record Invalid(Resolution.Invalid resolution) implements WalletResolution {

        public String errorDescription() {
            return resolution.getError().toString();
        }
    }
}
