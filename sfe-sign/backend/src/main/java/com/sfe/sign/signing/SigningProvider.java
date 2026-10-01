package com.sfe.sign.signing;

import com.sfe.sign.api.SignatureRequest;
import com.sfe.sign.api.SignatureResponse;
import com.sfe.sign.api.SigningCapabilities;

public interface SigningProvider {

    SigningCapabilities capabilities();

    SignatureResponse prepare(SignatureRequest request);
}

