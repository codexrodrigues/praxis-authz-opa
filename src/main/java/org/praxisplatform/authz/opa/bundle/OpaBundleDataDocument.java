package org.praxisplatform.authz.opa.bundle;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeRelease;

/**
 * Structured {@code data.json} document packaged inside an {@link OpaBundleArtifact}, exposing
 * {@link OpaRuntimeHead} at {@code /v1/data/praxis/authz/v1/runtime_head} ({@code CC11}, {@code OPA-SEARCH-001..004}).
 *
 * @param runtimeHead active runtime head descriptor
 * @param runtimeRelease 4-level OPA runtime lineage release metadata
 * @param unitKeysByDecisionPointKey index mapping each canonical {@code decisionPointKey} to its governing {@code policyUnitKey}s
 */
public record OpaBundleDataDocument(
        OpaRuntimeHead runtimeHead,
        OpaRuntimeRelease runtimeRelease,
        Map<String, List<String>> unitKeysByDecisionPointKey
) {

    /** Validates non-null head, release, and decision point index. */
    public OpaBundleDataDocument {
        runtimeHead = Objects.requireNonNull(runtimeHead, "runtimeHead is required");
        runtimeRelease = Objects.requireNonNull(runtimeRelease, "runtimeRelease is required");
        Objects.requireNonNull(unitKeysByDecisionPointKey, "unitKeysByDecisionPointKey is required");
        unitKeysByDecisionPointKey = Map.copyOf(unitKeysByDecisionPointKey);
    }
}
