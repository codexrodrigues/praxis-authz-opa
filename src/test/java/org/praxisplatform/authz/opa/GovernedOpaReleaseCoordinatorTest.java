package org.praxisplatform.authz.opa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator;
import org.praxisplatform.authz.opa.governance.PolicyCandidateVerificationCorpusCase;

/**
 * Conformance tests for {@link GovernedOpaReleaseCoordinator} ({@code P28}, {@code P32},
 * {@code P53}, {@code P55}, {@code P63}).
 */
class GovernedOpaReleaseCoordinatorTest {

    @Test
    void p28_p32_p53_p55_p63_releaseCoordinatorEnforcesAdminAuthorityApprovalDigestAndMandatoryCorpus() {
        String fcDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "fc");
        String qpDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "qp");
        String dpDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "dp");
        String capDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "opa-cap");

        var fc = RegoV1CompilerAndBundleAssemblerTest.sampleFactContract(fcDigest);
        QueryableResourceProjection qp = RegoV1CompilerAndBundleAssemblerTest.sampleQueryProjection(qpDigest);
        DecisionPointDescriptor dp = RegoV1CompilerAndBundleAssemblerTest.sampleDecisionPoint(fcDigest, qpDigest, dpDigest);
        AuthorizationPolicyDefinition policy = RegoV1CompilerAndBundleAssemblerTest.samplePolicy(
                "pol-hr-leave-requests", "unit:pol-hr-leave-requests:v1", dp.identity().pointKey(), dpDigest);

        ProviderInputProjection positiveInput = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                dp.identity().pointKey(),
                "SEARCH",
                fc.factContractDigest(),
                new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                Map.of(
                        "subject.principalId", "usr-manager-101",
                        "subject.organizationUnitIds", List.of(101L, 102L)
                ),
                Map.of(
                        "subject.principalId", FactResolutionStatus.PRESENT,
                        "subject.organizationUnitIds", FactResolutionStatus.PRESENT
                ),
                Set.of()
        );
        ProviderInputProjection negativeInput = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                dp.identity().pointKey(),
                "SEARCH",
                fc.factContractDigest(),
                new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                Map.of(
                        "subject.principalId", "usr-other-999",
                        "subject.organizationUnitIds", List.of(999L)
                ),
                Map.of(
                        "subject.principalId", FactResolutionStatus.PRESENT,
                        "subject.organizationUnitIds", FactResolutionStatus.PRESENT
                ),
                Set.of()
        );

        PolicyCandidateVerificationCorpusCase positiveCase = new PolicyCandidateVerificationCorpusCase(
                "case-pos-1",
                "Manager 101 receives ALLOW and department-scoped filter",
                EvaluationMode.SEARCH,
                positiveInput,
                null,
                GateOutcome.ALLOW,
                "ALLOW_DEPARTMENT_MANAGER",
                DataScopeOutcome.FILTER
        );
        PolicyCandidateVerificationCorpusCase negativeCase = new PolicyCandidateVerificationCorpusCase(
                "case-neg-1",
                "Other user does not receive rule grant",
                EvaluationMode.SEARCH,
                negativeInput,
                null,
                GateOutcome.NOT_APPLICABLE,
                null,
                DataScopeOutcome.NONE
        );

        GovernedOpaReleaseCoordinator coordinator = new GovernedOpaReleaseCoordinator();

        // 1. P28 / P32: Missing administrative authority POLICY_ADMIN_PUBLISH -> rejected with SecurityException!
        assertThrows(SecurityException.class, () ->
                coordinator.verifyAndActivateRelease(
                        "rel-1", "rev-1", "prod", "opa-1", capDigest,
                        "usr-regular", Set.of("REGULAR_USER"),
                        List.of(policy), Map.of(),
                        Map.of(dp.identity().pointKey(), dp),
                        Map.of(fc.factContractId(), fc),
                        Map.of(qp.projectionId(), qp),
                        List.of(positiveCase, negativeCase)
                )
        );

        // 2. P53 / P63: Corpus with only negative cases (denyAll false green) -> rejected!
        assertThrows(IllegalArgumentException.class, () ->
                coordinator.verifyAndActivateRelease(
                        "rel-1", "rev-1", "prod", "opa-1", capDigest,
                        "admin-sec", Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                        List.of(policy), Map.of(),
                        Map.of(dp.identity().pointKey(), dp),
                        Map.of(fc.factContractId(), fc),
                        Map.of(qp.projectionId(), qp),
                        List.of(negativeCase)
                )
        );

        // 3. P55: Mismatched approved definitionFingerprint -> rejected!
        String wrongDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEFINITION_FINGERPRINT, "tampered");
        assertThrows(IllegalArgumentException.class, () ->
                coordinator.verifyAndActivateRelease(
                        "rel-1", "rev-1", "prod", "opa-1", capDigest,
                        "admin-sec", Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                        List.of(policy), Map.of("pol-hr-leave-requests", wrongDigest),
                        Map.of(dp.identity().pointKey(), dp),
                        Map.of(fc.factContractId(), fc),
                        Map.of(qp.projectionId(), qp),
                        List.of(positiveCase, negativeCase)
                )
        );

        // 4. Valid governed activation with positive + negative corpus passes and emits receipt
        GovernedOpaReleaseCoordinator.GovernedReleaseActivationResult result = coordinator.verifyAndActivateRelease(
                "rel-1", "rev-1", "prod", "opa-1", capDigest,
                "admin-sec", Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                List.of(policy), Map.of(),
                Map.of(dp.identity().pointKey(), dp),
                Map.of(fc.factContractId(), fc),
                Map.of(qp.projectionId(), qp),
                List.of(positiveCase, negativeCase)
        );
        assertEquals("rev-1", result.activationReceipt().runtimeRevision());
        assertEquals(1, result.activationReceipt().positiveCorpusCasesPassed());
        assertEquals(1, result.activationReceipt().negativeCorpusCasesPassed());

        // 5. P3-R4 / P63: SEARCH corpus case with mismatched expectedReasonCode is rejected fail-closed!
        PolicyCandidateVerificationCorpusCase wrongReasonCase = new PolicyCandidateVerificationCorpusCase(
                "case-pos-wrong-reason",
                "Expected reason code does not match",
                EvaluationMode.SEARCH,
                positiveInput,
                null,
                GateOutcome.ALLOW,
                "WRONG_REASON_CODE",
                DataScopeOutcome.FILTER
        );
        assertThrows(IllegalStateException.class, () ->
                coordinator.verifyAndActivateRelease(
                        "rel-2", "rev-2", "prod", "opa-1", capDigest,
                        "admin-sec", Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                        List.of(policy), Map.of(),
                        Map.of(dp.identity().pointKey(), dp),
                        Map.of(fc.factContractId(), fc),
                        Map.of(qp.projectionId(), qp),
                        List.of(wrongReasonCase, negativeCase)
                )
        );
    }
}
