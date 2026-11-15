package org.praxisplatform.authz.opa.revision;

import java.util.Objects;
import java.util.function.Supplier;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;

/**
 * Enforces the 3-step {@code SEARCH} same-instance revision guard ({@code preflight -> compile -> postflight})
 * defined in {@code CC11} ({@code OPA-SEARCH-001..004}, {@code P17}, {@code P18}).
 *
 * <p>Guarantees that {@code SEARCH} admission and {@code DataScopePlan} compilation never mix two
 * different OPA instances or two different bundle revisions. If a legitimate bundle activation
 * occurs on the same instance between preflight and postflight, a bounded retry (default 1) is
 * attempted; if the instance changes or the revision still diverges, execution fails closed with
 * {@link OpaRevisionMismatchException}.</p>
 */
public final class SameInstanceSearchRevisionGuard {

    private final int maxSameInstanceRetries;

    /** Constructs a guard with 1 allowed retry on same-instance bundle rotation. */
    public SameInstanceSearchRevisionGuard() {
        this(1);
    }

    /**
     * Constructs a guard with the specified maximum retries on same-instance bundle rotation.
     *
     * @param maxSameInstanceRetries maximum retries when {@code instanceId} is preserved but {@code runtimeRevision} rotated (0..3)
     */
    public SameInstanceSearchRevisionGuard(int maxSameInstanceRetries) {
        if (maxSameInstanceRetries < 0 || maxSameInstanceRetries > 3) {
            throw new IllegalArgumentException("maxSameInstanceRetries must be between 0 and 3");
        }
        this.maxSameInstanceRetries = maxSameInstanceRetries;
    }

    /**
     * Executes a 3-step {@code SEARCH} sequence ({@code preflight -> compile -> postflight}) and
     * verifies {@link OpaRuntimeHead#verifySameInstanceSearchGuard(OpaRuntimeHead, OpaRuntimeHead)}.
     *
     * @param decisionPointKey canonical decision point key
     * @param step1PreflightSupplier step 1 supplier returning preflight head and admission result
     * @param step2CompileFunction step 2 function taking the preflight head and compiling the {@code DataScopePlan}
     * @param step3PostflightHeadSupplier step 3 supplier querying {@code /v1/data/praxis/authz/v1/runtime_head} on the same instance
     * @param <T> type of the combined search result
     * @return verified search result bound to a single consistent {@link OpaRuntimeHead}
     * @throws OpaRevisionMismatchException if instance drift occurs or revision consistency cannot be established
     */
    public <T> T executeGuardedSearch(
            String decisionPointKey,
            Supplier<OpaRuntimeHead> step1PreflightSupplier,
             java.util.function.Function<OpaRuntimeHead, T> step2CompileFunction,
            Supplier<OpaRuntimeHead> step3PostflightHeadSupplier
    ) {
        Objects.requireNonNull(decisionPointKey, "decisionPointKey is required");
        Objects.requireNonNull(step1PreflightSupplier, "step1PreflightSupplier is required");
        Objects.requireNonNull(step2CompileFunction, "step2CompileFunction is required");
        Objects.requireNonNull(step3PostflightHeadSupplier, "step3PostflightHeadSupplier is required");

        OpaRuntimeHead lastPreflight = null;
        OpaRuntimeHead lastPostflight = null;

        for (int attempt = 0; attempt <= maxSameInstanceRetries; attempt++) {
            lastPreflight = step1PreflightSupplier.get();
            if (lastPreflight == null) {
                throw new OpaRevisionMismatchException(
                        decisionPointKey,
                        null,
                        null,
                        "OPA SEARCH preflight returned null OpaRuntimeHead (P03 / OPA-SEARCH-001)");
            }

            T candidateResult = step2CompileFunction.apply(lastPreflight);
            lastPostflight = step3PostflightHeadSupplier.get();

            if (OpaRuntimeHead.verifySameInstanceSearchGuard(lastPreflight, lastPostflight)) {
                return candidateResult;
            }

            // If instanceId changed between preflight and postflight, fail closed immediately without retry!
            if (lastPostflight == null || !lastPreflight.instanceId().equals(lastPostflight.instanceId())) {
                throw new OpaRevisionMismatchException(
                        decisionPointKey,
                        lastPreflight,
                        lastPostflight,
                        "OPA instance changed during 3-step SEARCH evaluation for '" + decisionPointKey
                                + "': preflight=" + lastPreflight.instanceId()
                                + ", postflight=" + (lastPostflight == null ? "null" : lastPostflight.instanceId())
                                + " (P17 / OPA-SEARCH-004)");
            }
        }

        throw new OpaRevisionMismatchException(
                decisionPointKey,
                lastPreflight,
                lastPostflight,
                "OPA runtime revision rotated during 3-step SEARCH evaluation for '" + decisionPointKey
                        + "' and remained inconsistent after " + maxSameInstanceRetries + " retry(ies): preflight="
                        + (lastPreflight == null ? "null" : lastPreflight.runtimeRevision())
                        + ", postflight=" + (lastPostflight == null ? "null" : lastPostflight.runtimeRevision())
                        + " (P17 / P18 / OPA-SEARCH-004)");
    }
}
