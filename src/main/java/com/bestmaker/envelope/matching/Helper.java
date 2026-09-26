package com.bestmaker.envelope.matching;

import com.bestmaker.envelope.common.Capability;
import com.bestmaker.envelope.common.GridCell;
import com.bestmaker.envelope.common.HelperKind;
import com.bestmaker.envelope.common.TrustTier;

import java.util.Set;

/** 조력자. 시민 조력자는 가구 정보 없이 풀에만 등록된다. */
public record Helper(String id, HelperKind kind, GridCell cell, Set<Capability> capabilities) {
    public Helper {
        capabilities = Set.copyOf(capabilities);
    }

    public boolean canServe(Capability need) {
        return need == Capability.GENERAL || capabilities.contains(need);
    }

    public TrustTier tierFor(String designatedHelperId) {
        return TrustTier.of(kind, id, designatedHelperId);
    }

    public Helper movedTo(GridCell newCell) {
        return new Helper(id, kind, newCell, capabilities);
    }
}
