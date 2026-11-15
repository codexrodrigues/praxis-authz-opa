package org.praxisplatform.authz.opa.compiler;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.digest.OpaPolicyUnitManifest;
import org.praxisplatform.authz.contracts.digest.OpaProviderIoSchemas;
import org.praxisplatform.authz.contracts.digest.PolicyDigestChain;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyCandidateValidator;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyRule;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyValidationResult;
import org.praxisplatform.authz.contracts.policy.AuthorizationRuleContributions;
import org.praxisplatform.authz.contracts.policy.DefaultAuthorizationPolicyCandidateValidator;
import org.praxisplatform.authz.contracts.policy.FieldResolutionManifest;
import org.praxisplatform.authz.contracts.policy.FieldUseContributionSpec;
import org.praxisplatform.authz.contracts.policy.FieldWriteContributionSpec;
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.contracts.policy.PolicyMaterializationTargetSpec;
import org.praxisplatform.authz.contracts.policy.TargetResolutionManifest;

/**
 * Deterministic compiler translating validated {@link AuthorizationPolicyDefinition}s into
 * canonical Rego v1 modules ({@code import rego.v1}) and computing the 5-stage per-unit
 * {@link PolicyDigestChain} ({@code CC01}, {@code CC02}, {@code CC11}, {@code OPA-CMP-001..008},
 * {@code P03}, {@code P04}, {@code P30}, {@code P53}, {@code P63}).
 */
public final class RegoV1PolicyCompiler {

    /** Canonical path of the platform-owned system combining Rego module inside OPA bundles. */
    public static final String SYSTEM_COMBINING_MODULE_PATH = "praxis/authz/system/combining.rego";

    private final AuthorizationPolicyCandidateValidator candidateValidator;

    /** Constructs a compiler with the default {@link DefaultAuthorizationPolicyCandidateValidator}. */
    public RegoV1PolicyCompiler() {
        this(new DefaultAuthorizationPolicyCandidateValidator());
    }

    /**
     * Constructs a compiler with the given candidate validator.
     *
     * @param candidateValidator policy candidate validator
     */
    public RegoV1PolicyCompiler(AuthorizationPolicyCandidateValidator candidateValidator) {
        this.candidateValidator = Objects.requireNonNull(candidateValidator, "candidateValidator is required");
    }

    /**
     * Validates and compiles a single {@link AuthorizationPolicyDefinition} into a {@link CompiledRegoUnit}.
     *
     * @param policy candidate policy definition
     * @param decisionPointsByKey catalog of known decision points
     * @param factContractsById catalog of known fact contracts
     * @param queryProjectionsById catalog of known queryable resource projections
     * @return compiled Rego v1 unit with 5-stage digest chain
     * @throws IllegalArgumentException if candidate validation fails
     */
    public CompiledRegoUnit compileUnit(
            AuthorizationPolicyDefinition policy,
            Map<String, DecisionPointDescriptor> decisionPointsByKey,
            Map<String, FactContract> factContractsById,
            Map<String, QueryableResourceProjection> queryProjectionsById
    ) {
        Objects.requireNonNull(policy, "policy is required");
        AuthorizationPolicyValidationResult validation = candidateValidator.validate(
                policy, decisionPointsByKey, factContractsById, queryProjectionsById);
        if (!validation.valid()) {
            throw new IllegalArgumentException(
                    "Cannot compile invalid AuthorizationPolicyDefinition '" + policy.policyId()
                            + "': " + validation.diagnostics());
        }

        PolicyMaterializationTargetSpec matTarget = policy.materializationTargets().get(0);
        String policyUnitKey = matTarget.targetArtifactKey();
        String safeUnitPackageSuffix = sanitizeIdentifier(policy.policyId()) + "_" + sanitizeIdentifier(policy.version());
        String regoPackagePath = "praxis.authz.units." + safeUnitPackageSuffix;
        String moduleFilePath = "praxis/authz/units/" + safeUnitPackageSuffix + ".rego";

        Set<String> targetPointKeys = new LinkedHashSet<>();
        for (TargetResolutionManifest trm : validation.resolvedTargets()) {
            for (var ref : trm.resolvedPointRefs()) {
                targetPointKeys.add(ref.pointKey());
            }
        }

        String regoSource = generateRegoV1ModuleSource(
                regoPackagePath,
                policyUnitKey,
                policy,
                validation.resolvedTargets(),
                validation.resolvedFieldSelectors());

        // Compute the 5-stage per-unit PolicyDigestChain (CC11 / BND-DIG-001)
        String definitionPreimage = buildDefinitionPreimage(policy);
        String stage1DefDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEFINITION_FINGERPRINT, definitionPreimage);

        String depManifestPreimage = buildDependencyManifestPreimage(
                validation.resolvedTargets(), validation.resolvedFieldSelectors());
        String stage2DepDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, depManifestPreimage);

        String compileInputPreimage = stage1DefDigest + "|" + stage2DepDigest + "|" + OpaProviderIoSchemas.COMPILER_PROFILE_V1;
        String stage3CompileInputDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.COMPILE_INPUT_DIGEST, compileInputPreimage);

        String stage4GeneratedDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.GENERATED_ARTIFACT_DIGEST, stage3CompileInputDigest + "|" + regoSource);

        String stage5MatDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.MATERIALIZATION_FINGERPRINT,
                policyUnitKey + "|" + stage1DefDigest + "|" + stage4GeneratedDigest);

        PolicyDigestChain digestChain = new PolicyDigestChain(
                stage1DefDigest,
                stage2DepDigest,
                stage3CompileInputDigest,
                stage4GeneratedDigest,
                stage5MatDigest
        );

        OpaPolicyUnitManifest unitManifest = new OpaPolicyUnitManifest(
                policyUnitKey,
                policy.policyId(),
                policy.version(),
                regoPackagePath,
                digestChain,
                targetPointKeys
        );

        return new CompiledRegoUnit(
                unitManifest,
                moduleFilePath,
                regoSource,
                policy,
                validation.resolvedTargets(),
                validation.resolvedFieldSelectors()
        );
    }

    /**
     * Generates the platform-owned system combining Rego v1 module ({@code praxis/authz/system/combining.rego}).
     */
    public String generateSystemCombiningModuleSource(Collection<CompiledRegoUnit> units) {
        Objects.requireNonNull(units, "units is required");
        StringBuilder sb = new StringBuilder();
        sb.append("package praxis.authz.system.combining\n\n");
        sb.append("import rego.v1\n\n");
        sb.append("# Platform-owned 4-stage combining profile: ").append(OpaProviderIoSchemas.COMBINING_PROFILE_V1).append("\n");
        sb.append("# Precedence: DENY > ALLOW > NOT_APPLICABLE (Restriction veto dominates operational grant)\n\n");
        sb.append("combining_profile := \"").append(OpaProviderIoSchemas.COMBINING_PROFILE_V1).append("\"\n\n");
        sb.append("registered_unit_keys := [\n");
        for (CompiledRegoUnit unit : units) {
            sb.append("    \"").append(unit.unitManifest().policyUnitKey()).append("\",\n");
        }
        sb.append("]\n");
        return sb.toString();
    }

    private String generateRegoV1ModuleSource(
            String regoPackagePath,
            String policyUnitKey,
            AuthorizationPolicyDefinition policy,
            List<TargetResolutionManifest> resolvedTargets,
            Map<String, FieldResolutionManifest> resolvedFields
    ) {
        Map<String, Set<String>> attributesBySelectorHash = resolvedFields.values().stream()
                .collect(Collectors.toMap(
                        FieldResolutionManifest::selectorDigest,
                        FieldResolutionManifest::resolvedAttributeIds,
                        (a, b) -> a));

        StringBuilder sb = new StringBuilder();
        sb.append("package ").append(regoPackagePath).append("\n\n");
        sb.append("import rego.v1\n\n");
        sb.append("policy_unit_key := \"").append(policyUnitKey).append("\"\n");
        sb.append("policy_id := \"").append(policy.policyId()).append("\"\n");
        sb.append("policy_version := \"").append(policy.version()).append("\"\n");
        sb.append("legal_purpose := \"").append(policy.legalPurpose()).append("\"\n\n");

        sb.append("target_point_keys contains point_key if {\n");
        sb.append("    some point_key in [\n");
        for (TargetResolutionManifest trm : resolvedTargets) {
            for (var ref : trm.resolvedPointRefs()) {
                sb.append("        \"").append(ref.pointKey()).append("\",\n");
            }
        }
        sb.append("    ]\n}\n\n");

        for (AuthorizationPolicyRule rule : policy.rules()) {
            String safeRuleId = sanitizeIdentifier(rule.ruleId());
            String ruleFn = "rule_" + safeRuleId + "_matches";
            String whenFn = "rule_" + safeRuleId + "_when_matches";
            String modesLiteral = rule.evaluationModes().stream()
                    .map(Enum::name)
                    .sorted()
                    .map(m -> "\"" + m + "\"")
                    .collect(Collectors.joining(", "));
            sb.append("# Rule: ").append(rule.ruleId()).append(" — ").append(rule.description()).append("\n");
            emitDisjunctiveConditionBranches(sb, whenFn, rule.when().expression());

            AuthorizationRuleContributions contrib = rule.contributions();
            String dataScopeTargetFn = null;
            if (contrib.dataScope() != null && contrib.dataScope().resourceCondition() != null) {
                dataScopeTargetFn = "rule_" + safeRuleId + "_datascope_matches";
                String dsCondFn = "rule_" + safeRuleId + "_datascope_cond";
                emitDisjunctiveConditionBranches(sb, dsCondFn, contrib.dataScope().resourceCondition().expression());
                sb.append(dataScopeTargetFn).append(" if {\n    input.evaluationMode == \"SEARCH\"\n}\n\n");
                sb.append(dataScopeTargetFn).append(" if {\n    ").append(dsCondFn).append("\n}\n\n");
            }

            sb.append(ruleFn).append(" if {\n");
            sb.append("    target_point_keys[input.decisionPointKey]\n");
            sb.append("    input.evaluationMode in [").append(modesLiteral).append("]\n");
            sb.append("    ").append(whenFn).append("\n");
            if (dataScopeTargetFn != null) {
                sb.append("    ").append(dataScopeTargetFn).append("\n");
            }
            sb.append("}\n\n");

            if (contrib.access() != null) {
                sb.append("unit_contributions contains {\n");
                sb.append("    \"policyUnitKey\": policy_unit_key,\n");
                sb.append("    \"policyId\": policy_id,\n");
                sb.append("    \"ruleId\": \"").append(rule.ruleId()).append("\",\n");
                sb.append("    \"authority\": \"").append(contrib.access().authority().name()).append("\",\n");
                sb.append("    \"effect\": \"").append(contrib.access().effect().name()).append("\",\n");
                sb.append("    \"reasonCode\": \"").append(contrib.reasonCode()).append("\",\n");
                sb.append("} if {\n    ").append(ruleFn).append("\n}\n\n");
            } else if (contrib.dataScope() != null) {
                sb.append("unit_contributions contains {\n");
                sb.append("    \"policyUnitKey\": policy_unit_key,\n");
                sb.append("    \"policyId\": policy_id,\n");
                sb.append("    \"ruleId\": \"").append(rule.ruleId()).append("\",\n");
                sb.append("    \"authority\": \"").append(contrib.dataScope().authority().name()).append("\",\n");
                sb.append("    \"effect\": \"ALLOW\",\n");
                sb.append("    \"reasonCode\": \"").append(contrib.reasonCode()).append("\",\n");
                sb.append("} if {\n    ").append(ruleFn).append("\n}\n\n");
            }

            for (FieldUseContributionSpec fu : contrib.fieldUse()) {
                String selHash = CanonicalDigestCalculator.computeDigest(
                        DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, fu.fieldSelector().toCanonicalPreimage());
                Set<String> attrs = attributesBySelectorHash.getOrDefault(selHash, fu.fieldSelector().attributeIds());
                for (String attr : attrs) {
                    for (var cat : fu.categories()) {
                        sb.append("field_use_directives contains {\n");
                        sb.append("    \"attributeId\": \"").append(attr).append("\",\n");
                        sb.append("    \"category\": \"").append(cat.name()).append("\",\n");
                        sb.append("    \"effect\": \"").append(fu.effect().name()).append("\",\n");
                        sb.append("} if {\n    ").append(ruleFn).append("\n}\n\n");
                    }
                }
            }

            for (FieldWriteContributionSpec fw : contrib.fieldWrite()) {
                String selHash = CanonicalDigestCalculator.computeDigest(
                        DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, fw.fieldSelector().toCanonicalPreimage());
                Set<String> attrs = attributesBySelectorHash.getOrDefault(selHash, fw.fieldSelector().attributeIds());
                for (String attr : attrs) {
                    sb.append("field_write_directives contains {\n");
                    sb.append("    \"attributeId\": \"").append(attr).append("\",\n");
                    sb.append("    \"effect\": \"").append(fw.effect().name()).append("\",\n");
                    sb.append("} if {\n    ").append(ruleFn).append("\n}\n\n");
                }
            }

            for (MaskContributionSpec m : contrib.mask()) {
                String selHash = CanonicalDigestCalculator.computeDigest(
                        DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, m.fieldSelector().toCanonicalPreimage());
                Set<String> attrs = attributesBySelectorHash.getOrDefault(selHash, m.fieldSelector().attributeIds());
                for (String attr : attrs) {
                    sb.append("mask_directives contains {\n");
                    sb.append("    \"attributeId\": \"").append(attr).append("\",\n");
                    sb.append("    \"strategyId\": \"").append(m.strategyId()).append("\",\n");
                    sb.append("    \"parameters\": ").append(formatRegoLiteralValue(m.parameters())).append(",\n");
                    sb.append("} if {\n    ").append(ruleFn).append("\n}\n\n");
                }
            }

            for (ObligationDirective ob : rule.obligations()) {
                sb.append("obligation_directives contains {\n");
                sb.append("    \"obligationType\": \"").append(ob.obligationType()).append("\",\n");
                sb.append("    \"trigger\": \"").append(ob.trigger()).append("\",\n");
                sb.append("    \"fulfillmentBarrier\": \"").append(ob.fulfillmentBarrier()).append("\",\n");
                sb.append("    \"parameters\": ").append(formatRegoLiteralValue(ob.parameters())).append(",\n");
                sb.append("} if {\n    ").append(ruleFn).append("\n}\n\n");
            }
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private void emitDisjunctiveConditionBranches(StringBuilder sb, String predicateFnName, Map<String, Object> expr) {
        if (expr != null && expr.size() == 1 && "or".equals(expr.keySet().iterator().next())) {
            Object rawVal = expr.values().iterator().next();
            if (rawVal instanceof List<?> branches && !branches.isEmpty()) {
                for (Object branch : branches) {
                    if (branch instanceof Map<?, ?> branchMap) {
                        emitDisjunctiveConditionBranches(sb, predicateFnName, (Map<String, Object>) branchMap);
                    }
                }
                return;
            }
        }
        sb.append(predicateFnName).append(" if {\n");
        List<String> condLines = translateJsonLogicToRegoLines(expr);
        if (condLines.isEmpty()) {
            sb.append("    true\n");
        } else {
            for (String line : condLines) {
                sb.append("    ").append(line).append("\n");
            }
        }
        sb.append("}\n\n");
    }

    @SuppressWarnings("unchecked")
    private List<String> translateJsonLogicToRegoLines(Map<String, Object> expr) {
        List<String> lines = new ArrayList<>();
        if (expr == null || expr.isEmpty()) {
            return lines;
        }
        Map.Entry<String, Object> root = expr.entrySet().iterator().next();
        String op = root.getKey();
        Object val = root.getValue();

        if ("and".equals(op) && val instanceof List<?> children) {
            for (Object child : children) {
                if (child instanceof Map<?, ?> childMap) {
                    lines.addAll(translateJsonLogicToRegoLines((Map<String, Object>) childMap));
                }
            }
            return lines;
        }

        if ("or".equals(op) && val instanceof List<?> children) {
            List<String> branchExprs = new ArrayList<>();
            for (Object child : children) {
                if (child instanceof Map<?, ?> childMap) {
                    List<String> childLines = translateJsonLogicToRegoLines((Map<String, Object>) childMap);
                    if (!childLines.isEmpty()) {
                        branchExprs.add("(" + String.join(" && ", childLines) + ")");
                    }
                }
            }
            if (!branchExprs.isEmpty()) {
                lines.add("# disjunctive_or: " + String.join(" || ", branchExprs));
            }
            return lines;
        }

        if ("!".equals(op) || "not".equals(op)) {
            Map<String, Object> targetMap = null;
            if (val instanceof Map<?, ?> m) {
                targetMap = (Map<String, Object>) m;
            } else if (val instanceof List<?> list && !list.isEmpty() && list.get(0) instanceof Map<?, ?> m) {
                targetMap = (Map<String, Object>) m;
            }
            if (targetMap != null) {
                List<String> innerLines = new ArrayList<>();
                List<String> guardLines = new ArrayList<>();
                Map.Entry<String, Object> innerEntry = targetMap.entrySet().iterator().next();
                String innerOp = innerEntry.getKey();
                Object innerVal = innerEntry.getValue();
                if (innerVal instanceof List<?> args && args.size() == 2) {
                    String lhs = formatOperand(args.get(0), guardLines);
                    String rhs = formatOperand(args.get(1), guardLines);
                    lines.addAll(guardLines);
                    lines.add("not (" + buildBinaryComparisonExpr(innerOp, lhs, rhs) + ")");
                    return lines;
                }
                innerLines.addAll(translateJsonLogicToRegoLines(targetMap));
                for (String inner : innerLines) {
                    if (inner.startsWith("input.projectedFactStatuses[")) {
                        lines.add(inner);
                    } else {
                        lines.add("not (" + inner + ")");
                    }
                }
            }
            return lines;
        }

        if ("is_null".equals(op) || "is_not_null".equals(op)) {
            Object target = (val instanceof List<?> list && !list.isEmpty()) ? list.get(0) : val;
            if (target instanceof Map<?, ?> map && map.containsKey("var")) {
                String factPath = String.valueOf(map.get("var"));
                lines.add("input.projectedFactStatuses[\"" + factPath + "\"] == \""
                        + ("is_null".equals(op) ? "NULL" : "PRESENT") + "\"");
            }
            return lines;
        }

        if (val instanceof List<?> args && args.size() == 2) {
            String lhs = formatOperand(args.get(0), lines);
            String rhs = formatOperand(args.get(1), lines);
            lines.add(buildBinaryComparisonExpr(op, lhs, rhs));
        }
        return lines;
    }

    private static String buildBinaryComparisonExpr(String op, String lhs, String rhs) {
        return switch (op) {
            case "==" -> lhs + " == " + rhs;
            case "!=" -> lhs + " != " + rhs;
            case "in" -> lhs + " in " + rhs;
            case "nin" -> "not (" + lhs + " in " + rhs + ")";
            case ">" -> lhs + " > " + rhs;
            case ">=" -> lhs + " >= " + rhs;
            case "<" -> lhs + " < " + rhs;
            case "<=" -> lhs + " <= " + rhs;
            case "starts_with" -> "startswith(" + lhs + ", " + rhs + ")";
            case "ends_with" -> "endswith(" + lhs + ", " + rhs + ")";
            case "text_contains" -> "contains(" + lhs + ", " + rhs + ")";
            default -> "# operator: " + op;
        };
    }

    private String formatOperand(Object operand, List<String> guardLines) {
        if (operand instanceof Map<?, ?> map && map.containsKey("var")) {
            String factPath = String.valueOf(map.get("var"));
            // P04 / P30: Explicit PRESENT status check in Rego v1 against input.projectedFactStatuses so UNAVAILABLE/ABSENT/NULL never match!
            guardLines.add("input.projectedFactStatuses[\"" + factPath + "\"] == \"PRESENT\"");
            return "input.projectedInput[\"" + factPath + "\"]";
        }
        return formatRegoLiteralValue(operand);
    }

    private static String formatRegoLiteralValue(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String s) {
            return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
        if (value instanceof Map<?, ?> map) {
            if (map.isEmpty()) {
                return "{}";
            }
            return map.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey((a, b) -> String.valueOf(a).compareTo(String.valueOf(b))))
                    .map(e -> "\"" + String.valueOf(e.getKey()).replace("\"", "\\\"") + "\": " + formatRegoLiteralValue(e.getValue()))
                    .collect(Collectors.joining(", ", "{", "}"));
        }
        if (value instanceof Collection<?> col) {
            return col.stream()
                    .map(RegoV1PolicyCompiler::formatRegoLiteralValue)
                    .collect(Collectors.joining(", ", "[", "]"));
        }
        return String.valueOf(value);
    }

    private static String buildDefinitionPreimage(AuthorizationPolicyDefinition policy) {
        StringBuilder sb = new StringBuilder();
        sb.append(policy.schemaVersion()).append('|')
                .append(policy.policyId()).append('|')
                .append(policy.version()).append('|')
                .append(policy.title()).append('|')
                .append(policy.description()).append('|')
                .append(policy.policyPurposes().stream().sorted().collect(Collectors.joining(","))).append('|')
                .append(policy.legalPurpose()).append('|')
                .append(policy.legalBasisRef()).append('|')
                .append(policy.combiningProfileRef()).append('|')
                .append(policy.targets()).append('|')
                .append(policy.dualScopeDelegation()).append('|')
                .append(policy.factRequirements()).append('|')
                .append(policy.materializationTargets());
        for (AuthorizationPolicyRule r : policy.rules()) {
            sb.append("|rule:").append(r.ruleId())
                    .append(':').append(r.evaluationModes().stream().map(Enum::name).sorted().collect(Collectors.joining(",")))
                    .append(':').append(canonicalizeValue(r.when().expression()))
                    .append(':').append(r.contributions().access())
                    .append(':').append(r.contributions().dataScope() == null
                            ? "null"
                            : r.contributions().dataScope().authority() + ":"
                                    + canonicalizeValue(r.contributions().dataScope().resourceCondition().expression()))
                    .append(':').append(r.contributions().fieldUse())
                    .append(':').append(r.contributions().fieldWrite())
                    .append(':').append(r.contributions().mask())
                    .append(':').append(r.contributions().reasonCode())
                    .append(':').append(r.obligations());
        }
        return sb.toString();
    }

    private static String canonicalizeValue(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Map<?, ?> map) {
            return map.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey((a, b) -> String.valueOf(a).compareTo(String.valueOf(b))))
                    .map(e -> e.getKey() + "=" + canonicalizeValue(e.getValue()))
                    .collect(Collectors.joining(",", "{", "}"));
        }
        if (value instanceof Collection<?> col) {
            return col.stream()
                    .map(RegoV1PolicyCompiler::canonicalizeValue)
                    .collect(Collectors.joining(",", "[", "]"));
        }
        return String.valueOf(value);
    }

    private static String buildDependencyManifestPreimage(
            List<TargetResolutionManifest> targets,
            Map<String, FieldResolutionManifest> fields
    ) {
        StringBuilder sb = new StringBuilder();
        targets.stream()
                .sorted((a, b) -> a.targetId().compareTo(b.targetId()))
                .forEach(t -> sb.append("target:").append(t.targetId()).append(':')
                        .append(t.resolvedPointRefs().stream()
                                .map(r -> r.pointKey() + "@" + r.descriptorDigest())
                                .sorted()
                                .collect(Collectors.joining(",")))
                        .append('|'));
        fields.values().stream()
                .sorted((a, b) -> a.selectorDigest().compareTo(b.selectorDigest()))
                .forEach(f -> sb.append("field:").append(f.selectorDigest()).append(':')
                        .append(f.resolvedAttributeIds().stream().sorted().collect(Collectors.joining(",")))
                        .append('|'));
        return sb.toString();
    }

    private static String sanitizeIdentifier(String raw) {
        return raw.replaceAll("[^a-zA-Z0-9_]", "_").toLowerCase();
    }
}
