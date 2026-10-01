package com.sfe.sign.signing;

import eu.europa.esig.dss.enumerations.SignatureLevel;

final class DssPadesProfile {

    private DssPadesProfile() {
    }

    static SignatureLevel baselineLt() {
        return SignatureLevel.PAdES_BASELINE_LT;
    }
}

