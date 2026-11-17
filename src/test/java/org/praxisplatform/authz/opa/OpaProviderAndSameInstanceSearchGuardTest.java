package org.praxisplatform.authz.opa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.authority.EffectiveAuthorityBinding;
import org.praxisplatform.authz.contracts.authority.ExecutionDispositionMode;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.binding.HostEnforcementPhase;
import org.praxisplatform.authz.contracts.binding.ReadinessEvidenceOverlay;
import org.praxisplatform.authz.contracts.binding.ReadinessStage;
import org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding;
import org.praxisplatform.authz.contracts.binding.TransactionCardinality;
import org.praxisplatform.authz.contracts.context.ContextCompositionProfile;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointRef;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyRule;
import org.praxisplatform.authz.contracts.policy.AuthorizationRuleContributions;
import org.praxisplatform.authz.contracts.policy.AuthorizationSourceCondition;
import org.praxisplatform.authz.contracts.policy.ConditionProfileKind;
import org.praxisplatform.authz.contracts.policy.DataScopeContributionSpec;
import org.praxisplatform.authz.enforcement.context.ContextCompositionCoordinator;
import org.praxisplatform.authz.enforcement.context.TrustedFactSource;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.pipeline.EnforcementPipelineExecutor;
import org.praxisplatform.authz.enforcement.pipeline.HostDecisionNormalizationEngine;
import org.praxisplatform.authz.enforcement.pipeline.NormalizedEnforcementOutcome;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.opa.bundle.OpaBundleArtifact;
import org.praxisplatform.authz.opa.bundle.OpaBundleAssembler;
import org.praxisplatform.authz.opa.client.DeterministicLocalOpaTransport;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.compiler.CompiledRegoUnit;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;
import org.praxisplatform.authz.opa.revision.OpaEvaluationFailureException;
import org.praxisplatform.authz.opa.revision.OpaRevisionMismatchException;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;

/**
 * Conformance tests for {@link OpaAuthorizationProviderAdapter}, {@link SameInstanceSearchRevisionGuard},
 * and end-to-end integration with {@link EnforcementPipelineExecutor} ({@code CC03}, {@code CC07},
 * {@code CC11}, {@code P03}, {@code P17}, {@code P18}).
 */
class OpaProviderAndSameInstanceSearchGuardTest {

    @Test
    void p03_p17_opaAdapterExecutesSearchPipelineAndGuardsAgainstUndefinedResultTimeoutAndRevisionDrift() {
        String fcDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "fc");
        String qpDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "qp");
        String dpDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "dp");
        String capDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "opa-cap");

        FactContract fc = RegoV1CompilerAndBundleAssemblerTest.sampleFactContract(fcDigest);
        QueryableResourceProjection qp = RegoV1CompilerAndBundleAssemblerTest.sampleQueryProjection(qpDigest);
        DecisionPointDescriptor dp = RegoV1CompilerAndBundleAssemblerTest.sampleDecisionPoint(fcDigest, qpDigest, dpDigest);
        AuthorizationPolicyDefinition policy = RegoV1CompilerAndBundleAssemblerTest.samplePolicy(
                "pol-hr-leave-requests", "unit:pol-hr-leave-requests:v1", dp.identity().pointKey(), dpDigest);

        RegoV1PolicyCompiler compiler = new RegoV1PolicyCompiler();
        CompiledRegoUnit unit = compiler.compileUnit(
                policy,
                Map.of(dp.identity().pointKey(), dp),
                Map.of(fc.factContractId(), fc),
                Map.of(qp.projectionId(), qp)
        );
        OpaBundleAssembler assembler = new OpaBundleAssembler(compiler);
        OpaBundleArtifact bundleRev1 = assembler.assembleBundle(
                "rel-1", "rev-1", 1L, "prod-cluster-a", "opa-node-1", capDigest, List.of(unit));
        OpaBundleArtifact bundleRev2 = assembler.assembleBundle(
                "rel-2", "rev-2", 2L, "prod-cluster-a", "opa-node-1", capDigest, List.of(unit));

        DeterministicLocalOpaTransport transport = new DeterministicLocalOpaTransport(bundleRev1, List.of(qp));
        OpaAuthorizationProviderAdapter adapter = new OpaAuthorizationProviderAdapter(
                transport, new SameInstanceSearchRevisionGuard(1));

        ContextCompositionProfile admissionProfile = new ContextCompositionProfile(
                ContextCompositionProfile.SCHEMA_VERSION_V1,
                "prof-search",
                dp.identity().pointKey(),
                ContextEvaluationPhase.ADMISSION,
                fc.factContractId(),
                fc.factContractDigest(),
                Set.of("subject.principalId", "subject.organizationUnitIds"),
                Set.of(),
                200L,
                true
        );

        ContextCompositionCoordinator contextCoordinator = new ContextCompositionCoordinator(List.of(
                new TrustedFactSource() {
                    @Override
                    public FactResolutionStage stage() {
                        return FactResolutionStage.EXTRACT;
                    }

                    @Override
                    public Map<String, ResolvedFactValue> resolveFacts(
                            ContextEvaluationPhase phase,
                            Map<String, FactDescriptor> descriptorsToResolve,
                            Map<String, ResolvedFactValue> alreadyResolved
                    ) {
                        return Map.of("subject.principalId", ResolvedFactValue.present("subject.principalId", "usr-manager-101"));
                    }
                },
                new TrustedFactSource() {
                    @Override
                    public FactResolutionStage stage() {
                        return FactResolutionStage.ENRICH;
                    }

                    @Override
                    public Map<String, ResolvedFactValue> resolveFacts(
                            ContextEvaluationPhase phase,
                            Map<String, FactDescriptor> descriptorsToResolve,
                            Map<String, ResolvedFactValue> alreadyResolved
                    ) {
                        return Map.of("subject.organizationUnitIds", ResolvedFactValue.present("subject.organizationUnitIds", List.of(101L, 102L)));
                    }
                }
        ));

        RuntimeEnforcementBinding binding = new RuntimeEnforcementBinding(
                RuntimeEnforcementBinding.SCHEMA_VERSION_V1,
                "bind-filter",
                new DecisionPointRef(
                        dp.identity().pointKey(),
                        dp.identity().pointKind(),
                        dp.identity().serviceKey(),
                        dp.identity().resourceKey(),
                        dp.identity().operationOrActionKey(),
                        dpDigest),
                EvaluationMode.SEARCH,
                EnforcementCapability.DATA_SCOPE,
                Set.of(FieldUseCategory.VALUE, FieldUseCategory.FILTER),
                HostEnforcementPhase.REQUEST_QUERY,
                "OPA_REGO_V1",
                PointAuthorityMode.AUTHORITATIVE,
                "praxis.enforcement-profile.spring-jpa/v1",
                "DefaultSearchHandler/v1",
                "praxis.authz-host-contract/v1",
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.STATEMENT_ATOMIC,
                dpDigest,
                new ReadinessEvidenceOverlay(
                        Set.of(
                                ReadinessStage.STRUCTURAL_READY,
                                ReadinessStage.POLICY_READY,
                                ReadinessStage.PROVIDER_READY,
                                ReadinessStage.ENFORCEMENT_READY),
                        "rev-1",
                        dpDigest,
                        Instant.now()
                )
        );
        EffectiveAuthorityBinding authorityBinding = new EffectiveAuthorityBinding(
                "AUTHORITATIVE",
                ExecutionDispositionMode.AUTHORITATIVE_EXECUTION,
                PointAuthorityMode.AUTHORITATIVE
        );
        JpaDataScopeAdapter jpaAdapter = new JpaDataScopeAdapter(
                qp,
                List.of(new QueryAdapterFieldBinding(
                        "human-resources.leave-requests",
                        "resource.departmentId",
                        "hr.leave_requests.department_id",
                        "assignment.department.id",
                        RelationTraversalStrategy.INNER_JOIN_SCALAR,
                        true
                ))
        );

        EnforcementPipelineExecutor pipelineExecutor = new EnforcementPipelineExecutor(
                adapter,
                new HostDecisionNormalizationEngine(),
                new FieldUseQueryGuard(),
                new FieldWriteAuthorizer(),
                new DetachedDtoMaskingProcessor(),
                new ObligationBarrierCoordinator()
        );

        // 1. Happy path end-to-end SEARCH pipeline through OPA + JpaDataScopeAdapter
        NormalizedEnforcementOutcome searchOutcome = pipelineExecutor.executeSearchPipeline(
                binding,
                authorityBinding,
                true,
                true,
                Map.of(),
                contextCoordinator,
                fc,
                admissionProfile,
                new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                Set.of("subject.principalId", "subject.organizationUnitIds"),
                Map.of(),
                jpaAdapter,
                "e.tenantId = :hardTenantId",
                Map.of("hardTenantId", "tenant-alpha"),
                row -> true,
                Map.of()
        );
        assertTrue(searchOutcome.isPermitted());
        assertEquals(DataScopeOutcome.FILTER, searchOutcome.dataScopeCriterion().scopeOutcome());
        assertTrue(searchOutcome.dataScopeCriterion().composedWhereClause().contains("e.assignment.department.id IN (:dspParam1)"));

        // 2. P17: Single same-instance bundle rotation before postflight -> 1-shot retry recovers on rev-2!
        transport.setRotateBundleBeforePostflight(bundleRev2);
        NormalizedEnforcementOutcome retryOutcome = pipelineExecutor.executeSearchPipeline(
                binding,
                authorityBinding,
                true,
                true,
                Map.of(),
                contextCoordinator,
                fc,
                admissionProfile,
                new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                Set.of("subject.principalId", "subject.organizationUnitIds"),
                Map.of(),
                jpaAdapter,
                "e.tenantId = :hardTenantId",
                Map.of("hardTenantId", "tenant-alpha"),
                row -> true,
                Map.of()
        );
        assertTrue(retryOutcome.isPermitted());
        assertEquals("rev-2", retryOutcome.evidence().runtimeRevision());

        // 3. P17: Instance hop mid-flight (opa-node-1 -> opa-node-2) fails closed immediately with OpaRevisionMismatchException!
        transport.setOverridePostflightInstanceId("opa-node-2");
        ProviderInputProjection inputProj = contextCoordinator.composeAndProject(
                "SEARCH", fc, admissionProfile, new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                Set.of(), Set.of("subject.principalId", "subject.organizationUnitIds"));
        assertThrows(OpaRevisionMismatchException.class, () -> adapter.evaluateSearch(inputProj));
        transport.setOverridePostflightInstanceId(null);

        // 4. P03: Undefined result ({}) fails closed with AUTHZ_OPA_UNDEFINED_RESULT
        transport.setSimulateUndefinedResult(true);
        OpaEvaluationFailureException undefEx = assertThrows(
                OpaEvaluationFailureException.class, () -> adapter.evaluateTarget(inputProj, null));
        assertEquals("AUTHZ_OPA_UNDEFINED_RESULT", undefEx.getErrorCode());
        transport.setSimulateUndefinedResult(false);

        // 5. P03: Timeout fails closed with AUTHZ_OPA_TIMEOUT
        transport.setSimulateTimeout(true);
        OpaEvaluationFailureException timeoutEx = assertThrows(
                OpaEvaluationFailureException.class, () -> adapter.evaluateTarget(inputProj, null));
        assertEquals("AUTHZ_OPA_TIMEOUT", timeoutEx.getErrorCode());
        transport.setSimulateTimeout(false);

        // 6. P3-R4 / CTX-TMP-001: Deterministic evaluatedAt timestamp matches inputProjection.temporalContext().instant()
        var targetEnv = adapter.evaluateTarget(inputProj, null);
        assertEquals(inputProj.temporalContext().instant(), targetEnv.evaluatedAt());

        // 7. P3-R2 / CC12: Multiple DATA_SCOPE rules combine GRANT by union (OR) and RESTRICT by intersection (AND)
        var restrictRule = new AuthorizationPolicyRule(
                "rule-restrict-department",
                "Restricts scope to authorized department",
                Set.of(EvaluationMode.SEARCH),
                policy.rules().get(0).when(),
                new AuthorizationRuleContributions(
                        null,
                        new DataScopeContributionSpec(
                                ContributionAuthority.RESTRICT,
                                new AuthorizationSourceCondition(
                                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                        ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                        Map.of("==", List.of(Map.of("var", "resource.departmentId"), 101L))
                                )
                        ),
                        List.of(),
                        List.of(),
                        List.of(),
                        "RESTRICT_DEPARTMENT_101"
                ),
                List.of()
        );
        var multiScopePolicy = new AuthorizationPolicyDefinition(
                policy.schemaVersion(),
                policy.policyId(),
                policy.version(),
                policy.title(),
                policy.description(),
                policy.policyPurposes(),
                policy.legalPurpose(),
                policy.legalBasisRef(),
                policy.combiningProfileRef(),
                policy.targets(),
                policy.dualScopeDelegation(),
                policy.factRequirements(),
                List.of(policy.rules().get(0), restrictRule),
                policy.materializationTargets()
        );
        CompiledRegoUnit multiUnit = compiler.compileUnit(
                multiScopePolicy,
                Map.of(dp.identity().pointKey(), dp),
                Map.of(fc.factContractId(), fc),
                Map.of(qp.projectionId(), qp)
        );
        OpaBundleArtifact bundleRev3 = assembler.assembleBundle(
                "rel-3", "rev-3", 3L, "prod-cluster-a", "opa-node-1", capDigest, List.of(multiUnit));
        transport.activateBundle(bundleRev3);
        var combinedSearchRes = adapter.evaluateSearch(inputProj);
        assertEquals(DataScopeOutcome.FILTER, combinedSearchRes.dataScopePlan().scopeOutcome());
        assertEquals(
                SearchPredicateOperator.AND,
                combinedSearchRes.dataScopePlan().predicateIr().operator());
    }
}
