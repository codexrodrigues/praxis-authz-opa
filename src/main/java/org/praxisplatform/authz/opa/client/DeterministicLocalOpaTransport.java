package org.praxisplatform.authz.opa.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.datascope.ComparisonPredicateIr;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.FieldRefOperandIr;
import org.praxisplatform.authz.contracts.datascope.LiteralListOperandIr;
import org.praxisplatform.authz.contracts.datascope.LiteralOperandIr;
import org.praxisplatform.authz.contracts.datascope.LogicalPredicateIr;
import org.praxisplatform.authz.contracts.datascope.NullabilityPredicateIr;
import org.praxisplatform.authz.contracts.datascope.PushdownMode;
import org.praxisplatform.authz.contracts.datascope.QueryableFieldDescriptor;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateIr;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.digest.OpaProviderIoSchemas;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.FieldWriteEffectDirective;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.PolicyUnitContributionTrace;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyRule;
import org.praxisplatform.authz.contracts.policy.AuthorizationRuleContributions;
import org.praxisplatform.authz.contracts.policy.FieldResolutionManifest;
import org.praxisplatform.authz.contracts.policy.FieldUseContributionSpec;
import org.praxisplatform.authz.contracts.policy.FieldWriteContributionSpec;
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.opa.bundle.OpaBundleArtifact;
import org.praxisplatform.authz.opa.compiler.CompiledRegoUnit;
import org.praxisplatform.authz.opa.revision.OpaEvaluationFailureException;

/**
 * Deterministic in-memory implementation of {@link OpaClientTransport} that executes an activated
 * {@link OpaBundleArtifact} over the exact OPA REST wire contract ({@code {"input": ...}} ->
 * {@code {"result": ...}}) and supports fault injection for conformance testing ({@code CC11},
 * {@code P03}, {@code P17}, {@code P18}, {@code P24}, {@code P53}, {@code P63}).
 */
public final class DeterministicLocalOpaTransport implements OpaClientTransport {

    /** Canonical OPA data path for {@code TARGET} evaluation. */
    public static final String PATH_EVALUATE_TARGET = "/v1/data/praxis/authz/v1/evaluate_target";

    /** Canonical OPA data path for step 1 of {@code SEARCH} ({@code search_preflight}). */
    public static final String PATH_SEARCH_PREFLIGHT = "/v1/data/praxis/authz/v1/search_preflight";

    /** Canonical OPA data path for step 2 of {@code SEARCH} ({@code compile_data_scope}). */
    public static final String PATH_COMPILE_DATA_SCOPE = "/v1/data/praxis/authz/v1/compile_data_scope";

    /** Canonical OPA data path for step 3 of {@code SEARCH} ({@code runtime_head}). */
    public static final String PATH_RUNTIME_HEAD = "/v1/data/praxis/authz/v1/runtime_head";

    private final AtomicReference<OpaBundleArtifact> activeBundleRef;
    private final Map<String, QueryableResourceProjection> projectionsByResourceKey;
    private final ObjectMapper objectMapper;

    private volatile boolean simulateUndefinedResult = false;
    private volatile boolean simulateTimeout = false;
    private volatile OpaBundleArtifact rotateBundleBeforePostflight = null;
    private volatile String overridePostflightInstanceId = null;

    /**
     * Constructs a deterministic local OPA transport loaded with an initial {@link OpaBundleArtifact}.
     */
    public DeterministicLocalOpaTransport(
            OpaBundleArtifact initialBundle,
            Collection<QueryableResourceProjection> queryProjections
    ) {
        this.activeBundleRef = new AtomicReference<>(Objects.requireNonNull(initialBundle, "initialBundle is required"));
        Map<String, QueryableResourceProjection> map = new LinkedHashMap<>();
        if (queryProjections != null) {
            for (QueryableResourceProjection qp : queryProjections) {
                map.put(qp.resourceKey(), qp);
            }
        }
        this.projectionsByResourceKey = Map.copyOf(map);
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    /** Atomically activates a new {@link OpaBundleArtifact} in this local OPA runtime. */
    public void activateBundle(OpaBundleArtifact newBundle) {
        this.activeBundleRef.set(Objects.requireNonNull(newBundle, "newBundle is required"));
    }

    /** Returns the currently active {@link OpaBundleArtifact}. */
    public OpaBundleArtifact getActiveBundle() {
        return activeBundleRef.get();
    }

    /** Fault injection for {@code P03}: forces OPA to return {@code {}} without a {@code "result"} key. */
    public void setSimulateUndefinedResult(boolean simulateUndefinedResult) {
        this.simulateUndefinedResult = simulateUndefinedResult;
    }

    /** Fault injection for {@code P03}: forces OPA to throw a timeout exception. */
    public void setSimulateTimeout(boolean simulateTimeout) {
        this.simulateTimeout = simulateTimeout;
    }

    /**
     * Fault injection for {@code P17}: rotates the active bundle immediately before step 3 ({@code runtime_head})
     * to test {@code SameInstanceSearchRevisionGuard} retry/rejection behavior.
     */
    public void setRotateBundleBeforePostflight(OpaBundleArtifact nextBundle) {
        this.rotateBundleBeforePostflight = nextBundle;
    }

    /**
     * Fault injection for {@code P17}: overrides the serving {@code instanceId} reported on step 3
     * ({@code runtime_head}) to simulate a load-balancer instance hop mid-flight.
     */
    public void setOverridePostflightInstanceId(String overridePostflightInstanceId) {
        this.overridePostflightInstanceId = overridePostflightInstanceId;
    }

    @Override
    public OpaTransportResponse postDataQuery(
            String pinnedInstanceId,
            String opaDataPath,
            String requestJsonBody
    ) {
        if (simulateTimeout) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_TIMEOUT",
                    opaDataPath,
                    "Simulated OPA timeout on path " + opaDataPath + " (P03)");
        }
        if (simulateUndefinedResult) {
            return new OpaTransportResponse(
                    200,
                    activeBundleRef.get().runtimeHead().instanceId(),
                    "{}",
                    15L
            );
        }

        try {
            if (PATH_RUNTIME_HEAD.equals(opaDataPath) && rotateBundleBeforePostflight != null) {
                OpaBundleArtifact rotated = rotateBundleBeforePostflight;
                rotateBundleBeforePostflight = null;
                activeBundleRef.set(rotated);
            }

            OpaBundleArtifact bundle = activeBundleRef.get();
            OpaRuntimeHead currentHead = bundle.runtimeHead();
            String servingInstance = currentHead.instanceId();
            if (PATH_RUNTIME_HEAD.equals(opaDataPath) && overridePostflightInstanceId != null) {
                servingInstance = overridePostflightInstanceId;
                currentHead = new OpaRuntimeHead(
                        servingInstance,
                        currentHead.runtimeRevision(),
                        currentHead.headEtag(),
                        currentHead.activationRevision(),
                        currentHead.policySetDigest(),
                        currentHead.bundleArtifactDigest(),
                        currentHead.compilerProfileVersion(),
                        currentHead.opaCapabilitiesDigest()
                );
            }

            if (PATH_RUNTIME_HEAD.equals(opaDataPath)) {
                String json = objectMapper.writeValueAsString(Map.of("result", currentHead));
                return new OpaTransportResponse(200, servingInstance, json, 20L);
            }

            JsonNode root = objectMapper.readTree(requestJsonBody);
            JsonNode inputNode = root.get("input");
            if (inputNode == null || !inputNode.isObject()) {
                return new OpaTransportResponse(400, servingInstance, "{\"error\":\"missing input\"}", 10L);
            }

            if (PATH_EVALUATE_TARGET.equals(opaDataPath) || PATH_SEARCH_PREFLIGHT.equals(opaDataPath)) {
                EvaluationMode mode = PATH_SEARCH_PREFLIGHT.equals(opaDataPath)
                        ? EvaluationMode.SEARCH
                        : EvaluationMode.TARGET;
                Map<String, Object> resultPayload = evaluateUnitsForInput(bundle, currentHead, inputNode, mode);
                String json = objectMapper.writeValueAsString(Map.of("result", resultPayload));
                return new OpaTransportResponse(200, servingInstance, json, 45L);
            }

            if (PATH_COMPILE_DATA_SCOPE.equals(opaDataPath)) {
                Map<String, Object> ucastResult = compileDataScopeForInput(bundle, currentHead, inputNode);
                String json = objectMapper.writeValueAsString(Map.of("result", ucastResult));
                return new OpaTransportResponse(200, servingInstance, json, 55L);
            }

            return new OpaTransportResponse(404, servingInstance, "{\"error\":\"unknown path\"}", 10L);
        } catch (Exception ex) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_INTERNAL_ERROR",
                    opaDataPath,
                    "Deterministic local OPA evaluation error: " + ex.getMessage(),
                    ex);
        }
    }

    private Map<String, Object> evaluateUnitsForInput(
            OpaBundleArtifact bundle,
            OpaRuntimeHead head,
            JsonNode inputNode,
            EvaluationMode mode
    ) {
        String decisionPointKey = inputNode.path("decisionPointKey").asText("");
        String factContractDigest = inputNode.path("factContractDigest").asText("");
        JsonNode projectedInputNode = inputNode.path("projectedInput");
        JsonNode projectedStatusesNode = inputNode.path("projectedFactStatuses");

        List<PolicyUnitContributionTrace> unitTraces = new ArrayList<>();
        List<FieldUseEffectDirective> fieldUseDirs = new ArrayList<>();
        List<FieldWriteEffectDirective> fieldWriteDirs = new ArrayList<>();
        List<MaskDirective> maskDirs = new ArrayList<>();
        List<ObligationDirective> obligationDirs = new ArrayList<>();

        for (CompiledRegoUnit unit : bundle.compiledUnits()) {
            if (!unit.unitManifest().targetPointKeys().contains(decisionPointKey)) {
                continue;
            }
            Map<String, Set<String>> attrsByHash = new LinkedHashMap<>();
            for (FieldResolutionManifest frm : unit.resolvedFieldSelectors().values()) {
                attrsByHash.put(frm.selectorDigest(), frm.resolvedAttributeIds());
            }

            AuthorizationPolicyDefinition policy = unit.sourcePolicy();
            for (AuthorizationPolicyRule rule : policy.rules()) {
                if (!rule.evaluationModes().contains(mode)) {
                    continue;
                }
                if (!evaluateJsonLogicCondition(rule.when().expression(), projectedInputNode, projectedStatusesNode)) {
                    continue;
                }

                AuthorizationRuleContributions contrib = rule.contributions();
                if (mode == EvaluationMode.TARGET
                        && contrib.dataScope() != null
                        && hasAnyResourceFactStatus(projectedStatusesNode)
                        && !evaluateJsonLogicCondition(
                                contrib.dataScope().resourceCondition().expression(),
                                projectedInputNode,
                                projectedStatusesNode)) {
                    continue;
                }
                if (contrib.access() != null) {
                    unitTraces.add(new PolicyUnitContributionTrace(
                            unit.unitManifest().policyUnitKey(),
                            policy.policyId(),
                            rule.ruleId(),
                            contrib.access().authority(),
                            contrib.access().effect(),
                            contrib.reasonCode()
                    ));
                } else if (mode == EvaluationMode.SEARCH && contrib.dataScope() != null) {
                    unitTraces.add(new PolicyUnitContributionTrace(
                            unit.unitManifest().policyUnitKey(),
                            policy.policyId(),
                            rule.ruleId(),
                            contrib.dataScope().authority(),
                            RuleEffect.ALLOW,
                            contrib.reasonCode()
                    ));
                }

                for (FieldUseContributionSpec fu : contrib.fieldUse()) {
                    String selHash = CanonicalDigestCalculator.computeDigest(
                            DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, fu.fieldSelector().toCanonicalPreimage());
                    Set<String> attrs = attrsByHash.getOrDefault(selHash, fu.fieldSelector().attributeIds());
                    for (String attr : attrs) {
                        for (var cat : fu.categories()) {
                            fieldUseDirs.add(new FieldUseEffectDirective(attr, cat, fu.effect()));
                        }
                    }
                }

                for (FieldWriteContributionSpec fw : contrib.fieldWrite()) {
                    String selHash = CanonicalDigestCalculator.computeDigest(
                            DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, fw.fieldSelector().toCanonicalPreimage());
                    Set<String> attrs = attrsByHash.getOrDefault(selHash, fw.fieldSelector().attributeIds());
                    for (String attr : attrs) {
                        fieldWriteDirs.add(new FieldWriteEffectDirective(attr, fw.effect()));
                    }
                }

                for (MaskContributionSpec m : contrib.mask()) {
                    String selHash = CanonicalDigestCalculator.computeDigest(
                            DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, m.fieldSelector().toCanonicalPreimage());
                    Set<String> attrs = attrsByHash.getOrDefault(selHash, m.fieldSelector().attributeIds());
                    for (String attr : attrs) {
                        maskDirs.add(new MaskDirective(attr, m.strategyId(), m.parameters()));
                    }
                }

                obligationDirs.addAll(rule.obligations());
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", OpaProviderIoSchemas.TARGET_RESULT_V1);
        result.put("runtimeHead", head);
        result.put("decisionPointKey", decisionPointKey);
        result.put("evaluationMode", mode.name());
        result.put("factContractDigest", factContractDigest);
        result.put("unitContributions", unitTraces);
        result.put("fieldUseDirectives", fieldUseDirs);
        result.put("fieldWriteDirectives", fieldWriteDirs);
        result.put("maskDirectives", maskDirs);
        result.put("obligationDirectives", obligationDirs);
        return result;
    }

    private Map<String, Object> compileDataScopeForInput(
            OpaBundleArtifact bundle,
            OpaRuntimeHead head,
            JsonNode inputNode
    ) {
        String decisionPointKey = inputNode.path("decisionPointKey").asText("");
        String factContractDigest = inputNode.path("factContractDigest").asText("");
        JsonNode projectedInputNode = inputNode.path("projectedInput");
        JsonNode projectedStatusesNode = inputNode.path("projectedFactStatuses");

        // Extract resourceKey from decisionPointKey ("resource-operation/<resourceKey>/<operationId>" or "<service>/<resourceKey>/<op>")
        String[] parts = decisionPointKey.split("/");
        String resourceKey = parts.length >= 2 ? parts[parts.length - 2] : "unknown-resource";
        QueryableResourceProjection projection = resolveProjectionForDecisionPoint(decisionPointKey, resourceKey);
        if (projection == null) {
            throw new IllegalStateException("No QueryableResourceProjection registered for resourceKey: " + resourceKey);
        }

        List<SearchPredicateIr> grantPredicates = new ArrayList<>();
        List<SearchPredicateIr> restrictPredicates = new ArrayList<>();
        boolean anyGrantMatched = false;
        boolean unrestrictedGrantMatched = false;
        boolean anyAccessDenyMatched = false;

        for (CompiledRegoUnit unit : bundle.compiledUnits()) {
            if (!unit.unitManifest().targetPointKeys().contains(decisionPointKey)) {
                continue;
            }
            for (AuthorizationPolicyRule rule : unit.sourcePolicy().rules()) {
                if (!rule.evaluationModes().contains(EvaluationMode.SEARCH)) {
                    continue;
                }
                if (!evaluateJsonLogicCondition(rule.when().expression(), projectedInputNode, projectedStatusesNode)) {
                    continue;
                }
                var access = rule.contributions().access();
                if (access != null && access.effect() == RuleEffect.DENY) {
                    anyAccessDenyMatched = true;
                }
                var dataScope = rule.contributions().dataScope();
                if (dataScope != null) {
                    SearchPredicateIr pred = translateSearchConditionToIr(
                            dataScope.resourceCondition().expression(), projectedInputNode, projectedStatusesNode, projection);
                    if (dataScope.authority() == ContributionAuthority.GRANT) {
                        anyGrantMatched = true;
                        grantPredicates.add(pred);
                    } else {
                        restrictPredicates.add(pred);
                    }
                } else if (access != null
                        && access.authority() == ContributionAuthority.GRANT
                        && access.effect() == RuleEffect.ALLOW) {
                    anyGrantMatched = true;
                    unrestrictedGrantMatched = true;
                }
            }
        }

        // CC12 / PDP-CMB-004..005: Grants combine by union (OR); Restrictions combine by intersection (AND)
        SearchPredicateIr grantSurface = null;
        if (!unrestrictedGrantMatched && !grantPredicates.isEmpty()) {
            grantSurface = grantPredicates.size() == 1
                    ? grantPredicates.get(0)
                    : new LogicalPredicateIr(SearchPredicateOperator.OR, List.copyOf(grantPredicates));
        }

        SearchPredicateIr restrictSurface = null;
        if (!restrictPredicates.isEmpty()) {
            restrictSurface = restrictPredicates.size() == 1
                    ? restrictPredicates.get(0)
                    : new LogicalPredicateIr(SearchPredicateOperator.AND, List.copyOf(restrictPredicates));
        }

        SearchPredicateIr matchingPredicate;
        if (grantSurface != null && restrictSurface != null) {
            matchingPredicate = new LogicalPredicateIr(
                    SearchPredicateOperator.AND, List.of(grantSurface, restrictSurface));
        } else if (grantSurface != null) {
            matchingPredicate = grantSurface;
        } else {
            matchingPredicate = restrictSurface;
        }

        DataScopeOutcome outcome;
        if (anyAccessDenyMatched || !anyGrantMatched) {
            outcome = DataScopeOutcome.NONE;
        } else if (matchingPredicate == null) {
            outcome = DataScopeOutcome.ALL;
        } else {
            outcome = DataScopeOutcome.FILTER;
        }

        DataScopePlan plan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "dsp-" + head.runtimeRevision(),
                decisionPointKey,
                resourceKey,
                head.runtimeRevision(),
                head.policySetDigest(),
                factContractDigest,
                projection.projectionId(),
                projection.projectionDigest(),
                outcome,
                PushdownMode.FULL_PUSHDOWN,
                outcome == DataScopeOutcome.FILTER ? matchingPredicate : null
        );

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("schemaVersion", OpaProviderIoSchemas.UCAST_RESULT_V1);
        res.put("runtimeHead", head);
        res.put("dataScopePlan", plan);
        return res;
    }

    @SuppressWarnings("unchecked")
    private boolean evaluateJsonLogicCondition(
            Map<String, Object> expr,
            JsonNode projectedInputNode,
            JsonNode projectedStatusesNode
    ) {
        if (expr == null || expr.isEmpty()) {
            return false;
        }
        Map.Entry<String, Object> entry = expr.entrySet().iterator().next();
        String op = entry.getKey();
        Object rawVal = entry.getValue();

        if ("and".equals(op) && rawVal instanceof List<?> list) {
            for (Object item : list) {
                if (!evaluateJsonLogicCondition((Map<String, Object>) item, projectedInputNode, projectedStatusesNode)) {
                    return false;
                }
            }
            return true;
        }
        if ("or".equals(op) && rawVal instanceof List<?> list) {
            for (Object item : list) {
                if (evaluateJsonLogicCondition((Map<String, Object>) item, projectedInputNode, projectedStatusesNode)) {
                    return true;
                }
            }
            return false;
        }
        if ("!".equals(op) || "not".equals(op)) {
            if (rawVal instanceof Map<?, ?> child) {
                return !evaluateJsonLogicCondition((Map<String, Object>) child, projectedInputNode, projectedStatusesNode);
            }
            if (rawVal instanceof List<?> list && !list.isEmpty() && list.get(0) instanceof Map<?, ?> child) {
                return !evaluateJsonLogicCondition((Map<String, Object>) child, projectedInputNode, projectedStatusesNode);
            }
            return false;
        }

        if ("is_null".equals(op) || "is_not_null".equals(op)) {
            Object target = (rawVal instanceof List<?> list && !list.isEmpty()) ? list.get(0) : rawVal;
            if (target instanceof Map<?, ?> map && map.containsKey("var")) {
                String path = String.valueOf(map.get("var"));
                String status = projectedStatusesNode.path(path).asText("");
                return "is_null".equals(op) ? "NULL".equals(status) : "PRESENT".equals(status);
            }
            return false;
        }

        if (rawVal instanceof List<?> args && args.size() == 2) {
            ResolvedOperand lhs = resolveOperand(args.get(0), projectedInputNode, projectedStatusesNode);
            ResolvedOperand rhs = resolveOperand(args.get(1), projectedInputNode, projectedStatusesNode);
            if (!lhs.available() || !rhs.available()) {
                // P04 / P30: Unavailable, absent, or error facts never satisfy conditions!
                return false;
            }
            return switch (op) {
                case "==" -> Objects.equals(normalizeNumber(lhs.value()), normalizeNumber(rhs.value()));
                case "!=" -> !Objects.equals(normalizeNumber(lhs.value()), normalizeNumber(rhs.value()));
                case "<" -> compareNumbersOrStrings(lhs.value(), rhs.value()) < 0;
                case "<=" -> compareNumbersOrStrings(lhs.value(), rhs.value()) <= 0;
                case ">" -> compareNumbersOrStrings(lhs.value(), rhs.value()) > 0;
                case ">=" -> compareNumbersOrStrings(lhs.value(), rhs.value()) >= 0;
                case "in" -> {
                    if (rhs.value() instanceof Collection<?> col) {
                        Object target = normalizeNumber(lhs.value());
                        yield col.stream().map(DeterministicLocalOpaTransport::normalizeNumber)
                                .anyMatch(item -> Objects.equals(item, target));
                    }
                    yield false;
                }
                case "nin" -> {
                    if (rhs.value() instanceof Collection<?> col) {
                        Object target = normalizeNumber(lhs.value());
                        yield col.stream().map(DeterministicLocalOpaTransport::normalizeNumber)
                                .noneMatch(item -> Objects.equals(item, target));
                    }
                    yield false;
                }
                case "text_contains" -> String.valueOf(lhs.value()).contains(String.valueOf(rhs.value()));
                case "starts_with" -> String.valueOf(lhs.value()).startsWith(String.valueOf(rhs.value()));
                case "ends_with" -> String.valueOf(lhs.value()).endsWith(String.valueOf(rhs.value()));
                default -> false;
            };
        }
        return false;
    }

    private static int compareNumbersOrStrings(Object a, Object b) {
        if (a instanceof Number na && b instanceof Number nb) {
            return toBigDecimal(na).compareTo(toBigDecimal(nb));
        }
        return String.valueOf(a).compareTo(String.valueOf(b));
    }

    private record ResolvedOperand(boolean available, Object value) {}

    private ResolvedOperand resolveOperand(
            Object operand,
            JsonNode projectedInputNode,
            JsonNode projectedStatusesNode
    ) {
        if (operand instanceof Map<?, ?> map && map.containsKey("var")) {
            String path = String.valueOf(map.get("var"));
            String status = projectedStatusesNode.path(path).asText("");
            if (!"PRESENT".equals(status)) {
                return new ResolvedOperand(false, null);
            }
            Object converted = objectMapper.convertValue(projectedInputNode.get(path), Object.class);
            return new ResolvedOperand(true, converted);
        }
        return new ResolvedOperand(true, operand);
    }

    @SuppressWarnings("unchecked")
    private SearchPredicateIr translateSearchConditionToIr(
            Map<String, Object> expr,
            JsonNode projectedInputNode,
            JsonNode projectedStatusesNode,
            QueryableResourceProjection projection
    ) {
        Map.Entry<String, Object> entry = expr.entrySet().iterator().next();
        String op = entry.getKey();
        Object rawVal = entry.getValue();

        if ("and".equals(op) && rawVal instanceof List<?> list) {
            List<SearchPredicateIr> children = list.stream()
                    .map(item -> translateSearchConditionToIr(
                            (Map<String, Object>) item, projectedInputNode, projectedStatusesNode, projection))
                    .toList();
            return new LogicalPredicateIr(SearchPredicateOperator.AND, children);
        }
        if ("or".equals(op) && rawVal instanceof List<?> list) {
            List<SearchPredicateIr> children = list.stream()
                    .map(item -> translateSearchConditionToIr(
                            (Map<String, Object>) item, projectedInputNode, projectedStatusesNode, projection))
                    .toList();
            return new LogicalPredicateIr(SearchPredicateOperator.OR, children);
        }
        if ("!".equals(op) || "not".equals(op)) {
            Map<String, Object> childMap = rawVal instanceof List<?> list
                    ? (Map<String, Object>) list.get(0)
                    : (Map<String, Object>) rawVal;
            return new LogicalPredicateIr(
                    SearchPredicateOperator.NOT,
                    List.of(translateSearchConditionToIr(childMap, projectedInputNode, projectedStatusesNode, projection)));
        }
        if ("is_null".equals(op) || "is_not_null".equals(op)) {
            Object target = (rawVal instanceof List<?> list && !list.isEmpty()) ? list.get(0) : rawVal;
            Map<?, ?> lhsVar = (Map<?, ?>) target;
            String fieldPath = String.valueOf(lhsVar.get("var"));
            QueryableFieldDescriptor qfd = projection.fieldsByPath().get(fieldPath);
            if (qfd == null) {
                throw new IllegalArgumentException("Unknown queryable fieldPath: " + fieldPath);
            }
            return new NullabilityPredicateIr(
                    "is_null".equals(op) ? SearchPredicateOperator.IS_NULL : SearchPredicateOperator.IS_NOT_NULL,
                    qfd.fieldPath(),
                    qfd.attributeId()
            );
        }

        List<?> args = (List<?>) rawVal;
        Map<?, ?> lhsVar = (Map<?, ?>) args.get(0);
        String fieldPath = String.valueOf(lhsVar.get("var"));
        QueryableFieldDescriptor qfd = projection.fieldsByPath().get(fieldPath);
        if (qfd == null) {
            throw new IllegalArgumentException("Unknown queryable fieldPath: " + fieldPath);
        }

        // DSP-AST-010: Support FieldRefOperandIr when RHS is {"var": "resource.<targetField>"}
        if (args.get(1) instanceof Map<?, ?> rhsMap && rhsMap.containsKey("var")) {
            String rhsVarPath = String.valueOf(rhsMap.get("var"));
            if (rhsVarPath.startsWith("resource.")) {
                QueryableFieldDescriptor targetQfd = projection.fieldsByPath().get(rhsVarPath);
                if (targetQfd == null || !qfd.allowFieldRefComparison()) {
                    throw new IllegalArgumentException("Unsupported or disallowed FieldRef comparison: " + rhsVarPath);
                }
                return new ComparisonPredicateIr(
                        mapComparisonOperator(op),
                        qfd.fieldPath(),
                        qfd.attributeId(),
                        qfd.valueType(),
                        new FieldRefOperandIr(targetQfd.fieldPath(), targetQfd.attributeId()),
                        false
                );
            }
        }

        ResolvedOperand rhs = resolveOperand(args.get(1), projectedInputNode, projectedStatusesNode);
        if (!rhs.available() || rhs.value() == null) {
            throw new IllegalStateException("Subject fact required for SEARCH predicate is unavailable");
        }

        if (("in".equals(op) || "nin".equals(op)) && rhs.value() instanceof Collection<?> col) {
            List<Object> normalizedList = col.stream()
                    .map(v -> coerceToFieldType(v, qfd.valueType()))
                    .toList();
            return new ComparisonPredicateIr(
                    "in".equals(op) ? SearchPredicateOperator.IN : SearchPredicateOperator.NIN,
                    qfd.fieldPath(),
                    qfd.attributeId(),
                    qfd.valueType(),
                    new LiteralListOperandIr(normalizedList),
                    false
            );
        }
        return new ComparisonPredicateIr(
                mapComparisonOperator(op),
                qfd.fieldPath(),
                qfd.attributeId(),
                qfd.valueType(),
                new LiteralOperandIr(coerceToFieldType(rhs.value(), qfd.valueType())),
                false
        );
    }

    private static SearchPredicateOperator mapComparisonOperator(String op) {
        return switch (op) {
            case "==" -> SearchPredicateOperator.EQ;
            case "!=" -> SearchPredicateOperator.NE;
            case "<" -> SearchPredicateOperator.LT;
            case "<=" -> SearchPredicateOperator.LTE;
            case ">" -> SearchPredicateOperator.GT;
            case ">=" -> SearchPredicateOperator.GTE;
            case "text_contains" -> SearchPredicateOperator.TEXT_CONTAINS;
            case "starts_with" -> SearchPredicateOperator.STARTS_WITH;
            case "ends_with" -> SearchPredicateOperator.ENDS_WITH;
            default -> throw new IllegalArgumentException("Unsupported search condition operator: " + op);
        };
    }

    private QueryableResourceProjection resolveProjectionForDecisionPoint(String decisionPointKey, String candidateResourceKey) {
        QueryableResourceProjection direct = projectionsByResourceKey.get(candidateResourceKey);
        if (direct != null) {
            return direct;
        }
        for (QueryableResourceProjection qp : projectionsByResourceKey.values()) {
            if (decisionPointKey.contains("/" + qp.resourceKey() + "/")
                    || decisionPointKey.startsWith(qp.resourceKey() + "/")) {
                return qp;
            }
        }
        if (projectionsByResourceKey.size() == 1) {
            return projectionsByResourceKey.values().iterator().next();
        }
        return null;
    }

    private static Object coerceToFieldType(Object val, FactValueType valueType) {
        if (valueType == FactValueType.INT64 && val instanceof Number n) {
            return n.longValue();
        }
        if (valueType == FactValueType.DECIMAL && val instanceof Number n) {
            return toBigDecimal(n);
        }
        return val;
    }

    private static Object normalizeNumber(Object v) {
        if (v instanceof Integer || v instanceof Long || v instanceof Short || v instanceof Byte) {
            return ((Number) v).longValue();
        }
        if (v instanceof Number n) {
            BigDecimal bd = toBigDecimal(n).stripTrailingZeros();
            if (bd.scale() <= 0) {
                try {
                    return bd.longValueExact();
                } catch (ArithmeticException ignored) {
                    return bd;
                }
            }
            return bd;
        }
        return v;
    }

    private static BigDecimal toBigDecimal(Number n) {
        if (n instanceof BigDecimal bd) {
            return bd;
        }
        if (n instanceof Integer || n instanceof Long || n instanceof Short || n instanceof Byte) {
            return BigDecimal.valueOf(n.longValue());
        }
        return new BigDecimal(n.toString());
    }

    private static boolean hasAnyResourceFactStatus(JsonNode projectedStatusesNode) {
        if (projectedStatusesNode == null || !projectedStatusesNode.isObject()) {
            return false;
        }
        var fieldNames = projectedStatusesNode.fieldNames();
        while (fieldNames.hasNext()) {
            if (fieldNames.next().startsWith("resource.")) {
                return true;
            }
        }
        return false;
    }
}
