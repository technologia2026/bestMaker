package com.bestmaker.envelope.custodian;

import com.bestmaker.envelope.crypto.Layer;
import com.bestmaker.envelope.evidence.Evidence;

import java.util.List;

public record OpenRequest(String householdId, Layer layer, Requester requester, List<Evidence> evidence) {
    public OpenRequest {
        evidence = evidence == null ? List.of() : List.copyOf(evidence);
    }
}
