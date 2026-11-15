package org.praxisplatform.authz.opa.governance;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.opa.bundle.OpaBundleArtifact;
import org.praxisplatform.authz.opa.bundle.OpaBundleAssembler;
import org.praxisplatform.authz.opa.client.DeterministicLocalOpaTransport;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.compiler.CompiledRegoUnit;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;

/**
 * Coordinates the governed control-plane release pipeline for authorization policies
 * ({@code CC01}, {@code CC02}, {@code CC11}, {@code CC12}, {@code P28}, {@code P32}, {@code P37},
 * {@code P38}, {@code P53}, {@code P55}, {@code P63}).
 *
 * <p>Enforces:
 * <ol>
 *   <li>Administrative authority gate ({@code P28}, {@code P32}): requires {@code POLICY_ADMIN_PUBLISH} authority;</li>
 *   <li>Candidate validation and Rego v1 compilation ({@code P37});</li>
 *   <li>Exact approval digest verification ({@code P55}): rejects activation if a candidate changed after approval;</li>
 *   <li>Competing authoritative unit detection ({@code P38});</li>
 *   <li>Mandatory positive + negative corpus execution against the compiled bundle ({@code P53}, {@code P63}:
 *       rejects zero-test releases, {@code denyAll} false greens, or corpus mismatches).</li>
 * </ol>
 */
public final class GovernedOpaReleaseCoordinator {

    /** Canonical administrative authority required to publish, activate, or withdraw policies ({@code P28}, {@code P32}). */
    public static final String REQUIRED_ADMIN_AUTHORITY = "POLICY_ADMIN_PUBLISH";

    private final RegoV1PolicyCompiler compiler;
    private final OpaBundleAssembler bundleAssembler;
    private final AtomicLong monotonicActivationCounter = new AtomicLong(0L);

    /** Constructs a release coordinator with default compiler and bundle assembler. */
    public GovernedOpaReleaseCoordinator() {
        this(new RegoV1PolicyCompiler(), new OpaBundleAssembler());
    }

    /** Constructs a release coordinator with the given compiler and bundle assembler. */
    public GovernedOpaReleaseCoordinator(
            RegoV1PolicyCompiler compiler,
            OpaBundleAssembler bundleAssembler
    ) {
        this.compiler = Objects.requireNonNull(compiler, "compiler is required");
        this.bundleAssembler = Objects.requireNonNull(bundleAssembler, "bundleAssembler is required");
    }

    /**
     * Result of a governed compilation, corpus verification, and bundle activation.
     */
    public record GovernedReleaseActivationResult(
            OpaBundleArtifact bundleArtifact,
            PolicyCandidateActivationReceipt activationReceipt
    ) {}

    /**
     * Validates, compiles, verifies against the independent corpus, and packages an {@link OpaBundleArtifact}
     * with a signed {@link PolicyCandidateActivationReceipt}.
     */
    public GovernedReleaseActivationResult verifyAndActivateRelease(
            String releaseId,
            String runtimeRevision,
            String environmentKey,
            String instanceId,
            String opaCapabilitiesDigest,
            String adminPrincipalId,
            Set<String> callerAdminAuthorities,
            Collection<AuthorizationPolicyDefinition> candidatePolicies,
            Map<String, String> expectedApprovedDefinitionFingerprintsByPolicyId,
            Map<String, DecisionPointDescriptor> decisionPointsByKey,
            Map<String, FactContract> factContractsById,
            Map<String, QueryableResourceProjection> queryProjectionsById,
            List<PolicyCandidateVerificationCorpusCase> verificationCorpus
    ) {
        // 1. P28 / P32: Enforce administrative authority before any publication or activation
        if (adminPrincipalId == null || adminPrincipalId.isBlank()
                || callerAdminAuthorities == null
                || !callerAdminAuthorities.contains(REQUIRED_ADMIN_AUTHORITY)) {
            throw new SecurityException(
                    "Caller lacks required administrative authority '" + REQUIRED_ADMIN_AUTHORITY
                            + "' to publish or activate authorization policies (P28 / P32)");
        }

        if (verificationCorpus == null || verificationCorpus.isEmpty()) {
            throw new IllegalArgumentException(
                    "Verification corpus must not be empty; zero-test policy activation is forbidden (P53 / P63)");
        }

        // 2. Compile and validate each candidate policy (P37)
        List<CompiledRegoUnit> compiledUnits = new ArrayList<>();
        Map<String, String> actualFingerprints = new LinkedHashMap<>();
        for (AuthorizationPolicyDefinition policy : candidatePolicies) {
            CompiledRegoUnit unit = compiler.compileUnit(
                    policy, decisionPointsByKey, factContractsById, queryProjectionsById);
            compiledUnits.add(unit);
            String actualFp = unit.unitManifest().digestChain().definitionFingerprint();
            actualFingerprints.put(policy.policyId(), actualFp);

            // 3. P55: Verify exact approved definition fingerprint if pinned by approval workflow
            if (expectedApprovedDefinitionFingerprintsByPolicyId != null
                    && expectedApprovedDefinitionFingerprintsByPolicyId.containsKey(policy.policyId())) {
                String expectedFp = expectedApprovedDefinitionFingerprintsByPolicyId.get(policy.policyId());
                if (!actualFp.equals(expectedFp)) {
                    throw new IllegalArgumentException(
                            "Candidate policy '" + policy.policyId()
                                    + "' changed after approval: expected definitionFingerprint=" + expectedFp
                                    + ", actual=" + actualFp + " (P55)");
                }
            }
        }

        // 4. Assemble bundle across all 8 digest domains and check P38 competing unit keys
        long activationRev = monotonicActivationCounter.incrementAndGet();
        OpaBundleArtifact bundle = bundleAssembler.assembleBundle(
                releaseId,
                runtimeRevision,
                activationRev,
                environmentKey,
                instanceId,
                opaCapabilitiesDigest,
                compiledUnits
        );

        // 5. P53 / P63: Execute mandatory positive and negative corpus cases against the compiled bundle
        DeterministicLocalOpaTransport stagingTransport = new DeterministicLocalOpaTransport(
                bundle, queryProjectionsById.values());
        OpaAuthorizationProviderAdapter stagingAdapter = new OpaAuthorizationProviderAdapter(stagingTransport);

        int positivePassed = 0;
        int negativePassed = 0;

        for (PolicyCandidateVerificationCorpusCase testCase : verificationCorpus) {
            if (testCase.evaluationMode() == EvaluationMode.TARGET) {
                ProviderEvaluationEnvelope env = stagingAdapter.evaluateTarget(
                        testCase.inputProjection(), testCase.writeIntent());
                if (env.gateOutcome() != testCase.expectedGateOutcome()) {
                    throw new IllegalStateException(
                            "Corpus case '" + testCase.caseId() + "' failed: expected gateOutcome="
                                    + testCase.expectedGateOutcome() + ", actual=" + env.gateOutcome() + " (P63)");
                }
                if (testCase.expectedReasonCode() != null) {
                    boolean reasonMatched = env.unitContributions().stream()
                            .anyMatch(t -> testCase.expectedReasonCode().equals(t.reasonCode()));
                    if (!reasonMatched) {
                        throw new IllegalStateException(
                                "Corpus case '" + testCase.caseId() + "' failed: expected reasonCode="
                                        + testCase.expectedReasonCode() + " not present in unitContributions (P63)");
                    }
                }
            } else {
                AuthorizationProviderPort.SearchProviderEvaluationResult searchRes =
                        stagingAdapter.evaluateSearch(testCase.inputProjection());
                if (searchRes.admissionEnvelope().gateOutcome() != testCase.expectedGateOutcome()) {
                    throw new IllegalStateException(
                            "SEARCH corpus case '" + testCase.caseId() + "' failed: expected gateOutcome="
                                    + testCase.expectedGateOutcome() + ", actual="
                                    + searchRes.admissionEnvelope().gateOutcome() + " (P63)");
                }
                if (testCase.expectedDataScopeOutcome() != null
                        && searchRes.dataScopePlan().scopeOutcome() != testCase.expectedDataScopeOutcome()) {
                    throw new IllegalStateException(
                            "SEARCH corpus case '" + testCase.caseId() + "' failed: expected dataScopeOutcome="
                                    + testCase.expectedDataScopeOutcome() + ", actual="
                                    + searchRes.dataScopePlan().scopeOutcome() + " (P63)");
                }
                if (testCase.expectedReasonCode() != null) {
                    boolean reasonMatched = searchRes.admissionEnvelope().unitContributions().stream()
                            .anyMatch(t -> testCase.expectedReasonCode().equals(t.reasonCode()));
                    if (!reasonMatched) {
                        throw new IllegalStateException(
                                "SEARCH corpus case '" + testCase.caseId() + "' failed: expected reasonCode="
                                        + testCase.expectedReasonCode() + " not present in unitContributions (P63)");
                    }
                }
            }

            if (testCase.isPositiveCase()) {
                positivePassed++;
            } else {
                negativePassed++;
            }
        }

        if (positivePassed < 1 || negativePassed < 1) {
            throw new IllegalArgumentException(
                    "Corpus verification rejected false-green release: positivePassed=" + positivePassed
                            + ", negativePassed=" + negativePassed
                            + " (both must be >= 1; denyAll or allowAll without counter-proof is forbidden by P53 / P63)");
        }

        PolicyCandidateActivationReceipt receipt = new PolicyCandidateActivationReceipt(
                releaseId,
                runtimeRevision,
                activationRev,
                adminPrincipalId,
                actualFingerprints,
                bundle.runtimeRelease().policySetDigest(),
                bundle.runtimeRelease().bundleArtifactDigest(),
                positivePassed,
                negativePassed,
                Instant.now()
        );

        return new GovernedReleaseActivationResult(bundle, receipt);
    }
}
