package org.praxisplatform.authz.opa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactCardinality;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.FactSlotNamespace;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.datascope.QueryableFieldDescriptor;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionKind;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointIdentity;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionResultContractKind;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FactContractRef;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.decisionpoint.QueryableProjectionRef;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.digest.OpaProviderIoSchemas;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.AccessContributionSpec;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyRule;
import org.praxisplatform.authz.contracts.policy.AuthorizationRuleContributions;
import org.praxisplatform.authz.contracts.policy.AuthorizationSourceCondition;
import org.praxisplatform.authz.contracts.policy.ConditionProfileKind;
import org.praxisplatform.authz.contracts.policy.DataScopeContributionSpec;
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.contracts.policy.PolicyFieldSelector;
import org.praxisplatform.authz.contracts.policy.PolicyMaterializationTargetSpec;
import org.praxisplatform.authz.contracts.policy.PolicyTargetSpec;
import org.praxisplatform.authz.opa.bundle.OpaBundleArtifact;
import org.praxisplatform.authz.opa.bundle.OpaBundleAssembler;
import org.praxisplatform.authz.opa.client.DeterministicLocalOpaTransport;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.compiler.CompiledRegoUnit;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;

/**
 * Conformance tests for {@link RegoV1PolicyCompiler} and {@link OpaBundleAssembler}
 * ({@code CC01}, {@code CC02}, {@code CC11}, {@code P04}, {@code P30}, {@code P38}, {@code P53}).
 */
class RegoV1CompilerAndBundleAssemblerTest {

    static FactContract sampleFactContract(String fcDigest) {
        FactDescriptor subPrincipal = new FactDescriptor(
                "subject.principalId", FactSlotNamespace.SUBJECT, FactValueType.STRING, FactCardinality.SCALAR,
                FactPresenceModel.ALWAYS_PRESENT, null, null, FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET), false,
                "INTERNAL", "OPERATIONAL", Set.of(), "HUMAN_RESOURCES_ADMINISTRATION", null);
        FactDescriptor subOrgs = new FactDescriptor(
                "subject.organizationUnitIds", FactSlotNamespace.SUBJECT, FactValueType.INT64, FactCardinality.SET,
                FactPresenceModel.ALWAYS_PRESENT, null, null, FactResolutionStage.ENRICH,
                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET), false,
                "INTERNAL", "OPERATIONAL", Set.of(), "HUMAN_RESOURCES_ADMINISTRATION", null);
        FactDescriptor resDepartment = new FactDescriptor(
                "resource.departmentId", FactSlotNamespace.RESOURCE, FactValueType.INT64, FactCardinality.SCALAR,
                FactPresenceModel.ALWAYS_PRESENT, "hr.leave_requests.department_id", null, FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.TARGET), true,
                "INTERNAL", "OPERATIONAL", Set.of(), "HUMAN_RESOURCES_ADMINISTRATION", null);
        FactDescriptor resMedicalCode = new FactDescriptor(
                "resource.medicalCode", FactSlotNamespace.RESOURCE, FactValueType.STRING, FactCardinality.SCALAR,
                FactPresenceModel.MAY_BE_ABSENT, "hr.leave_requests.medical_code", null, FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.TARGET), true,
                "RESTRICTED", "SENSITIVE_PERSONAL", Set.of("HEALTH_DATA"), "OFFICIAL_HEALTH_EXPERTISE", null);

        return new FactContract(
                FactContract.SCHEMA_VERSION_V1,
                "fc-leave-requests",
                "1.0.0",
                fcDigest,
                "human-resources.leave-requests",
                Map.of(
                        subPrincipal.factPath(), subPrincipal,
                        subOrgs.factPath(), subOrgs,
                        resDepartment.factPath(), resDepartment,
                        resMedicalCode.factPath(), resMedicalCode
                )
        );
    }

    static QueryableResourceProjection sampleQueryProjection(String qpDigest) {
        return new QueryableResourceProjection(
                QueryableResourceProjection.SCHEMA_VERSION_V1,
                "qp-leave-requests",
                "human-resources.leave-requests",
                qpDigest,
                Map.of(
                        "resource.departmentId",
                        new QueryableFieldDescriptor(
                                "resource.departmentId",
                                "hr.leave_requests.department_id",
                                FactValueType.INT64,
                                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN),
                                true)
                )
        );
    }

    static DecisionPointDescriptor sampleDecisionPoint(String fcDigest, String qpDigest, String dpDigest) {
        DecisionPointIdentity dpId = DecisionPointIdentity.resourceOperation(
                "workforce-service", "human-resources.leave-requests", "filter");
        return new DecisionPointDescriptor(
                DecisionPointDescriptor.SCHEMA_VERSION_V1,
                dpId,
                DecisionKind.AUTHORIZATION,
                DecisionResultContractKind.GATE,
                null,
                "SEARCH",
                "POST",
                "/api/human-resources/leave-requests/filter",
                Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET),
                Set.of(EnforcementCapability.ACCESS, EnforcementCapability.DATA_SCOPE, EnforcementCapability.FIELD_USE, EnforcementCapability.MASK),
                Set.of(FieldUseCategory.VALUE, FieldUseCategory.FILTER, FieldUseCategory.SORT, FieldUseCategory.GROUP, FieldUseCategory.AGGREGATE, FieldUseCategory.JOIN),
                null,
                new FactContractRef("fc-leave-requests", fcDigest),
                new QueryableProjectionRef("qp-leave-requests", qpDigest),
                null,
                null,
                "HUMAN_RESOURCES_ADMINISTRATION",
                "LGPD:ART_7_III",
                null,
                dpDigest
        );
    }

    static AuthorizationPolicyDefinition samplePolicy(String policyId, String unitKey, String dpKey, String dpDigest) {
        AuthorizationPolicyRule rule = new AuthorizationPolicyRule(
                "rule-department-scope",
                "Grants read access by department and masks restricted medical code",
                Set.of(EvaluationMode.TARGET, EvaluationMode.SEARCH),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        Map.of("==", List.of(Map.of("var", "subject.principalId"), "usr-manager-101"))
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        new DataScopeContributionSpec(
                                ContributionAuthority.GRANT,
                                new AuthorizationSourceCondition(
                                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                        ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                        Map.of("in", List.of(
                                                Map.of("var", "resource.departmentId"),
                                                Map.of("var", "subject.organizationUnitIds")))
                                )
                        ),
                        List.of(),
                        List.of(),
                        List.of(new MaskContributionSpec(
                                PolicyFieldSelector.exact(Set.of("hr.leave_requests.medical_code")),
                                "REDACT_CONSTANT",
                                Map.of("replacement", "***RESTRICTED-CODE***")
                        )),
                        "ALLOW_DEPARTMENT_MANAGER"
                ),
                List.of(new ObligationDirective(
                        "DURABLE_AUDIT_EVIDENCE",
                        "ON_PERMIT",
                        "BEFORE_COMMIT_OUTBOX",
                        Map.of("auditCategory", "LEAVE_REQUEST_QUERY")))
        );

        return new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                policyId,
                "1.0.0",
                "Leave Request Policy",
                "Department scope and sensitive code masking",
                Set.of("ORGANIZATIONAL_SCOPE"),
                "HUMAN_RESOURCES_ADMINISTRATION",
                "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact("tgt-1", dpKey, dpDigest, Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET))),
                null,
                List.of(),
                List.of(rule),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine", "opa-policy", unitKey, OpaProviderIoSchemas.COMPILER_PROFILE_V1))
        );
    }

    @Test
    void cc11_p38_p53_compilerGeneratesDeterministicRegoV1AndAssemblerRejectsCompetingUnits() {
        String fcDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "fc");
        String qpDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "qp");
        String dpDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "dp");
        String capDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "opa-cap");

        FactContract fc = sampleFactContract(fcDigest);
        QueryableResourceProjection qp = sampleQueryProjection(qpDigest);
        DecisionPointDescriptor dp = sampleDecisionPoint(fcDigest, qpDigest, dpDigest);
        AuthorizationPolicyDefinition policy = samplePolicy(
                "pol-hr-leave-requests", "unit:pol-hr-leave-requests:v1", dp.identity().pointKey(), dpDigest);

        RegoV1PolicyCompiler compiler = new RegoV1PolicyCompiler();
        CompiledRegoUnit unit1 = compiler.compileUnit(
                policy,
                Map.of(dp.identity().pointKey(), dp),
                Map.of(fc.factContractId(), fc),
                Map.of(qp.projectionId(), qp)
        );
        CompiledRegoUnit unit2 = compiler.compileUnit(
                policy,
                Map.of(dp.identity().pointKey(), dp),
                Map.of(fc.factContractId(), fc),
                Map.of(qp.projectionId(), qp)
        );

        // Determinism of Rego v1 output and all 5 per-unit digest stages
        assertEquals(unit1.regoSource(), unit2.regoSource());
        assertEquals(unit1.unitManifest().digestChain(), unit2.unitManifest().digestChain());
        assertTrue(unit1.regoSource().contains("import rego.v1"));
        // P04 / P30 / P10-R01: Rego v1 checks projectedFactStatuses == "PRESENT" before comparing projectedInput value
        assertTrue(unit1.regoSource().contains("input.projectedFactStatuses[\"subject.principalId\"] == \"PRESENT\""));
        assertTrue(unit1.regoSource().contains("input.projectedInput[\"subject.principalId\"] == \"usr-manager-101\""));
        assertTrue(unit1.regoSource().contains("rule_rule_department_scope_datascope_matches"));
        assertTrue(unit1.regoSource().contains("\"parameters\": {\"replacement\": \"***RESTRICTED-CODE***\"}"));
        assertTrue(unit1.regoSource().contains("\"parameters\": {\"auditCategory\": \"LEAVE_REQUEST_QUERY\"}"));

        // Assemble 4-level OPA bundle
        OpaBundleAssembler assembler = new OpaBundleAssembler(compiler);
        OpaBundleArtifact bundleA = assembler.assembleBundle(
                "rel-1", "rev-2026-11-08-01", 1L, "prod-cluster-a", "opa-node-1", capDigest, List.of(unit1));
        OpaBundleArtifact bundleB = assembler.assembleBundle(
                "rel-1", "rev-2026-11-08-01", 1L, "prod-cluster-a", "opa-node-1", capDigest, List.of(unit2));

        assertEquals(bundleA.runtimeRelease().bundleArtifactDigest(), bundleB.runtimeRelease().bundleArtifactDigest());
        assertTrue(bundleA.bundleArchiveBytes().length > 0);
        assertNotNull(bundleA.dataDocument().unitKeysByDecisionPointKey().get(dp.identity().pointKey()));

        // P10-R03 (CC11 / BND-DIG-001): Multi-unit bundle assembly is 100% commutative (order-independent)
        AuthorizationPolicyDefinition secondPolicy = samplePolicy(
                "pol-hr-leave-requests-secondary", "unit:pol-hr-leave-requests-secondary:v1", dp.identity().pointKey(), dpDigest);
        CompiledRegoUnit secondUnit = compiler.compileUnit(
                secondPolicy,
                Map.of(dp.identity().pointKey(), dp),
                Map.of(fc.factContractId(), fc),
                Map.of(qp.projectionId(), qp)
        );
        OpaBundleArtifact bundleOrder12 = assembler.assembleBundle(
                "rel-comm", "rev-comm-1", 10L, "prod-cluster-a", "opa-node-1", capDigest, List.of(unit1, secondUnit));
        OpaBundleArtifact bundleOrder21 = assembler.assembleBundle(
                "rel-comm", "rev-comm-1", 10L, "prod-cluster-a", "opa-node-1", capDigest, List.of(secondUnit, unit1));
        assertEquals(bundleOrder12.systemCombiningRegoSource(), bundleOrder21.systemCombiningRegoSource());
        assertEquals(bundleOrder12.runtimeRelease().policySetDigest(), bundleOrder21.runtimeRelease().policySetDigest());
        assertEquals(bundleOrder12.runtimeRelease().bundleArtifactDigest(), bundleOrder21.runtimeRelease().bundleArtifactDigest());

        // P38: Two units disputing the same policyUnitKey or policyId must be rejected fail-closed!
        assertThrows(IllegalArgumentException.class, () ->
                assembler.assembleBundle(
                        "rel-conflict", "rev-conflict", 2L, "prod-cluster-a", "opa-node-1", capDigest, List.of(unit1, unit2))
        );

        // P3-R3 / P55: Mutating rule condition or effect while preserving ruleId and reasonCode MUST change Stage-1 definitionFingerprint
        AuthorizationPolicyRule modifiedRule = new AuthorizationPolicyRule(
                policy.rules().get(0).ruleId(),
                policy.rules().get(0).description(),
                policy.rules().get(0).evaluationModes(),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        Map.of("==", List.of(Map.of("var", "subject.principalId"), "usr-other-999"))
                ),
                policy.rules().get(0).contributions(),
                policy.rules().get(0).obligations()
        );
        AuthorizationPolicyDefinition tamperedPolicy = new AuthorizationPolicyDefinition(
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
                List.of(modifiedRule),
                policy.materializationTargets()
        );
        CompiledRegoUnit tamperedUnit = compiler.compileUnit(
                tamperedPolicy,
                Map.of(dp.identity().pointKey(), dp),
                Map.of(fc.factContractId(), fc),
                Map.of(qp.projectionId(), qp)
        );
        assertNotEquals(
                unit1.unitManifest().digestChain().definitionFingerprint(),
                tamperedUnit.unitManifest().digestChain().definitionFingerprint());

        // P10-R01 & P10-R02: Disjunctive ("or") / negated ("not") compilation and exact BigDecimal evaluation without truncation
        AuthorizationPolicyRule orDecimalRule = new AuthorizationPolicyRule(
                "r-or-decimal",
                "Tests OR, NOT, and untruncated decimal precision",
                Set.of(EvaluationMode.TARGET),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        Map.of("or", List.of(
                                Map.of("==", List.of(Map.of("var", "subject.principalId"), "usr-decimal-12-50")),
                                Map.of("!", List.of(Map.of("==", List.of(Map.of("var", "subject.principalId"), "usr-blocked"))))
                        ))
                ),
                policy.rules().get(0).contributions(),
                List.of()
        );
        AuthorizationPolicyDefinition orPolicy = new AuthorizationPolicyDefinition(
                policy.schemaVersion(),
                "pol-or-decimal",
                "1.0.0",
                policy.title(),
                policy.description(),
                policy.policyPurposes(),
                policy.legalPurpose(),
                policy.legalBasisRef(),
                policy.combiningProfileRef(),
                policy.targets(),
                null,
                List.of(),
                List.of(orDecimalRule),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine", "opa-policy", "unit:pol-or-decimal:v1", OpaProviderIoSchemas.COMPILER_PROFILE_V1))
        );
        CompiledRegoUnit orUnit = compiler.compileUnit(
                orPolicy,
                Map.of(dp.identity().pointKey(), dp),
                Map.of(fc.factContractId(), fc),
                Map.of(qp.projectionId(), qp)
        );
        assertTrue(orUnit.regoSource().contains("rule_r_or_decimal_when_matches if {"));
        assertTrue(orUnit.regoSource().contains("not (input.projectedInput[\"subject.principalId\"] == \"usr-blocked\")"));

        // Verify DeterministicLocalOpaTransport distinguishes 12.50 from 12.75 (no longValue truncation)
        AuthorizationPolicyRule decComparisonRule = new AuthorizationPolicyRule(
                "r-dec-cmp",
                "Compares exact decimal value 12.50",
                Set.of(EvaluationMode.TARGET),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        Map.of("==", List.of(Map.of("var", "resource.departmentId"), new BigDecimal("12.50")))
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        null, List.of(), List.of(), List.of(), "ALLOW_EXACT_DECIMAL"
                ),
                List.of()
        );
        AuthorizationPolicyDefinition decPolicy = new AuthorizationPolicyDefinition(
                policy.schemaVersion(),
                "pol-dec-cmp",
                "1.0.0",
                policy.title(),
                policy.description(),
                policy.policyPurposes(),
                policy.legalPurpose(),
                policy.legalBasisRef(),
                policy.combiningProfileRef(),
                policy.targets(),
                null,
                List.of(),
                List.of(decComparisonRule),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine", "opa-policy", "unit:pol-dec-cmp:v1", OpaProviderIoSchemas.COMPILER_PROFILE_V1))
        );
        OpaBundleArtifact decBundle = assembler.assembleBundle(
                "rel-dec", "rev-dec-1", 20L, "prod-cluster-a", "opa-node-1", capDigest,
                List.of(compiler.compileUnit(
                        decPolicy,
                        Map.of(dp.identity().pointKey(), dp),
                        Map.of(fc.factContractId(), fc),
                        Map.of(qp.projectionId(), qp)
                ))
        );
        var localTransport = new DeterministicLocalOpaTransport(decBundle, List.of(qp));
        var adapter = new OpaAuthorizationProviderAdapter(
                localTransport,
                new SameInstanceSearchRevisionGuard(1)
        );
        var eval1275 = adapter.evaluateTarget(
                new ProviderInputProjection(
                        ProviderInputProjection.SCHEMA_VERSION_V1,
                        dp.identity().pointKey(),
                        "TARGET",
                        fcDigest,
                        new TemporalContext(Instant.now(), ZoneOffset.UTC),
                        Map.of("resource.departmentId", new BigDecimal("12.75")),
                        Map.of("resource.departmentId", FactResolutionStatus.PRESENT),
                        Set.of()
                ),
                null
        );
        assertEquals(GateOutcome.NOT_APPLICABLE, eval1275.gateOutcome());
        var eval1250 = adapter.evaluateTarget(
                new ProviderInputProjection(
                        ProviderInputProjection.SCHEMA_VERSION_V1,
                        dp.identity().pointKey(),
                        "TARGET",
                        fcDigest,
                        new TemporalContext(Instant.now(), ZoneOffset.UTC),
                        Map.of("resource.departmentId", new BigDecimal("12.50")),
                        Map.of("resource.departmentId", FactResolutionStatus.PRESENT),
                        Set.of()
                ),
                null
        );
        assertEquals(GateOutcome.ALLOW, eval1250.gateOutcome());
    }
}
