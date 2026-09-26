package com.bestmaker.envelope.matching;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 조력자 자격 명부 (담당 공무원이 관리). 보관 기관도 이 자격을 직접 확인한다.
 * 이상 탐지로 정지된 계정은 즉시 자격을 잃는다.
 */
public final class HelperRegistry {
    private final Map<String, Helper> helpers = new ConcurrentHashMap<>();
    private final Set<String> suspended = ConcurrentHashMap.newKeySet();

    public void register(Helper h) {
        helpers.put(h.id(), h);
    }

    public void updateLocation(Helper moved) {
        helpers.computeIfPresent(moved.id(), (k, v) -> moved);
    }

    public Optional<Helper> find(String id) {
        return id == null ? Optional.empty() : Optional.ofNullable(helpers.get(id));
    }

    /** 등록돼 있고 정지되지 않았는가. */
    public boolean isQualified(String id) {
        return id != null && helpers.containsKey(id) && !suspended.contains(id);
    }

    public void suspend(String id) {
        suspended.add(id);
    }

    public boolean isSuspended(String id) {
        return suspended.contains(id);
    }

    public Collection<Helper> active() {
        return List.copyOf(helpers.values().stream().filter(h -> !suspended.contains(h.id())).toList());
    }
}
