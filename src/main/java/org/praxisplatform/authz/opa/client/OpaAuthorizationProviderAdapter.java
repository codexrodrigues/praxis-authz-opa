package org.praxisplatform.authz.opa.client;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.datascope.ComparisonPredicateIr;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.FieldRefOperandIr;
import org.praxisplatform.authz.contracts.datascope.LiteralListOperandIr;
import org.praxisplatform.authz.contracts.datascope.LiteralOperandIr;
import org.praxisplatform.authz.contracts.datascope.LogicalPredicateIr;
import org.praxisplatform.authz.contracts.datascope.NullabilityPredicateIr;
import org.praxisplatform.authz.contracts.datascope.PushdownMode;
import org.praxisplatform.authz.contracts.datascope.RightOperandIr;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateIr;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.digest.OpaProviderIoSchemas;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.FieldWriteEffectDirective;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.PolicyUnitContributionTrace;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.opa.revision.OpaEvaluationFailureException;
import org.praxisplatform.authz.opa.revision.OpaRevisionMismatchException;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;

/**
 * Implements {@link AuthorizationProviderPort} over {@link OpaClientTransport}, enforcing:
 * <ul>
 *   <li>Versioned OPA input/result contracts ({@code praxis.opa-target-input/v1}, {@code praxis.opa-target-result/v1},
 *       {@code praxis.opa-search-input/v1}, {@code praxis.opa-ucast-result/v1} — {@code CC11});</li>
 *   <li>Fail-closed rejection of undefined {@code result}, non-200 HTTP status, or malformed responses ({@code P03});</li>
 *   <li>Algebraic combining precedence ({@code DENY > ALLOW > NOT_APPLICABLE}, restriction veto over operational grant — {@code CC12});</li>
 *   <li>3-step {@code SEARCH} same-instance revision guard via {@link SameInstanceSearchRevisionGuard} ({@code P17}, {@code P18}).</li>
 * </ul>
 */
public final class OpaAuthorizationProviderAdapter implements AuthorizationProviderPort {

    private static final TypeReference<List<PolicyUnitContributionTrace>> TRACE_LIST_TYPE = new TypeReference<>() {};
    private static final TypeReference<List<FieldUseEffectDirective>> FIELD_USE_LIST_TYPE = new TypeReference<>() {};
    private static final TypeReference<List<FieldWriteEffectDirective>> FIELD_WRITE_LIST_TYPE = new TypeReference<>() {};
    private static final TypeReference<List<MaskDirective>> MASK_LIST_TYPE = new TypeReference<>() {};
    private static final TypeReference<List<ObligationDirective>> OBLIGATION_LIST_TYPE = new TypeReference<>() {};

    private final OpaClientTransport transport;
    private final SameInstanceSearchRevisionGuard searchRevisionGuard;
    private final ObjectMapper objectMapper;

    /** Constructs an adapter with the given transport and a default 1-retry {@link SameInstanceSearchRevisionGuard}. */
    public OpaAuthorizationProviderAdapter(OpaClientTransport transport) {
        this(transport, new SameInstanceSearchRevisionGuard(1));
    }

    /**
     * Constructs an adapter with the given transport and {@link SameInstanceSearchRevisionGuard}.
     */
    public OpaAuthorizationProviderAdapter(
            OpaClientTransport transport,
            SameInstanceSearchRevisionGuard searchRevisionGuard
    ) {
        this.transport = Objects.requireNonNull(transport, "transport is required");
        this.searchRevisionGuard = Objects.requireNonNull(searchRevisionGuard, "searchRevisionGuard is required");
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @Override
    public ProviderEvaluationEnvelope evaluateTarget(
            ProviderInputProjection inputProjection,
            WriteIntent writeIntent
    ) {
        Objects.requireNonNull(inputProjection, "inputProjection is required");
        String dpKey = extractDecisionPointKey(inputProjection);
        Map<String, Object> opaInput = buildOpaInputEnvelope(
                OpaProviderIoSchemas.TARGET_INPUT_V1, dpKey, inputProjection, writeIntent);

        OpaTransportResponse response = executePost(
                null,
                DeterministicLocalOpaTransport.PATH_EVALUATE_TARGET,
                dpKey,
                opaInput);
        JsonNode resultNode = extractRequiredResultNode(
                response, dpKey, OpaProviderIoSchemas.TARGET_RESULT_V1);
        Instant evaluatedAt = inputProjection.temporalContext() != null
                ? inputProjection.temporalContext().instant()
                : Instant.now();
        return buildProviderEnvelope(resultNode, dpKey, EvaluationMode.TARGET, response.latencyMicros(), evaluatedAt);
    }

    @Override
    public SearchProviderEvaluationResult evaluateSearch(ProviderInputProjection inputProjection) {
        Objects.requireNonNull(inputProjection, "inputProjection is required");
        String dpKey = extractDecisionPointKey(inputProjection);
        Map<String, Object> opaInput = buildOpaInputEnvelope(
                OpaProviderIoSchemas.SEARCH_INPUT_V1, dpKey, inputProjection, null);
        Instant evaluatedAt = inputProjection.temporalContext() != null
                ? inputProjection.temporalContext().instant()
                : Instant.now();

        AtomicReference<ProviderEvaluationEnvelope> preflightEnvelopeRef = new AtomicReference<>();
        AtomicReference<OpaRuntimeHead> preflightHeadRef = new AtomicReference<>();
        AtomicReference<OpaRuntimeHead> compileHeadMismatchRef = new AtomicReference<>();

        return searchRevisionGuard.executeGuardedSearch(
                dpKey,
                () -> {
                    // Step 1: search_preflight
                    compileHeadMismatchRef.set(null);
                    OpaTransportResponse preResp = executePost(
                            null,
                            DeterministicLocalOpaTransport.PATH_SEARCH_PREFLIGHT,
                            dpKey,
                            opaInput);
                    JsonNode resNode = extractRequiredResultNode(
                            preResp, dpKey, OpaProviderIoSchemas.TARGET_RESULT_V1);
                    OpaRuntimeHead head = parseRuntimeHead(resNode.get("runtimeHead"), dpKey, preResp.instanceId());
                    ProviderEvaluationEnvelope env = buildProviderEnvelope(
                            resNode, dpKey, EvaluationMode.SEARCH, preResp.latencyMicros(), evaluatedAt);
                    preflightEnvelopeRef.set(env);
                    preflightHeadRef.set(head);
                    return head;
                },
                preflightHead -> {
                    // Step 2: compile_data_scope pinned to preflightHead.instanceId()
                    OpaTransportResponse compResp = executePost(
                            preflightHead.instanceId(),
                            DeterministicLocalOpaTransport.PATH_COMPILE_DATA_SCOPE,
                            dpKey,
                            opaInput);
                    JsonNode ucastNode = extractRequiredResultNode(
                            compResp, dpKey, OpaProviderIoSchemas.UCAST_RESULT_V1);
                    OpaRuntimeHead compileHead = parseRuntimeHead(
                            ucastNode.get("runtimeHead"), dpKey, compResp.instanceId());
                    if (!OpaRuntimeHead.verifySameInstanceSearchGuard(preflightHead, compileHead)) {
                        if (!preflightHead.instanceId().equals(compileHead.instanceId())) {
                            throw new OpaRevisionMismatchException(
                                    dpKey,
                                    preflightHead,
                                    compileHead,
                                    "OPA instance changed between search_preflight and compile_data_scope for '"
                                            + dpKey + "' (P17 / OPA-SEARCH-004)");
                        }
                        compileHeadMismatchRef.set(compileHead);
                    }
                    DataScopePlan plan = parseDataScopePlan(ucastNode.get("dataScopePlan"), dpKey);
                    if (!compileHead.runtimeRevision().equals(plan.runtimeRevision())
                            || !compileHead.policySetDigest().equals(plan.policySetDigest())) {
                        throw new OpaRevisionMismatchException(
                                dpKey,
                                preflightHead,
                                compileHead,
                                "DataScopePlan revision/digest does not match compile_data_scope runtimeHead for '"
                                        + dpKey + "' (P17 / OPA-SEARCH-004)");
                    }
                    return new SearchProviderEvaluationResult(preflightEnvelopeRef.get(), plan);
                },
                () -> {
                    // Step 3: runtime_head postflight check pinned to preflightHead.instanceId()
                    if (compileHeadMismatchRef.get() != null) {
                        return compileHeadMismatchRef.get();
                    }
                    OpaRuntimeHead preHead = preflightHeadRef.get();
                    String pinnedInstance = preHead == null ? null : preHead.instanceId();
                    OpaTransportResponse headResp = executePost(
                            pinnedInstance,
                            DeterministicLocalOpaTransport.PATH_RUNTIME_HEAD,
                            dpKey,
                            Map.of());
                    JsonNode headNode = extractRequiredResultNode(headResp, dpKey, null);
                    return parseRuntimeHead(headNode, dpKey, headResp.instanceId());
                }
        );
    }

    private OpaTransportResponse executePost(
            String pinnedInstanceId,
            String path,
            String decisionPointKey,
            Map<String, Object> inputPayload
    ) {
        try {
            String body = objectMapper.writeValueAsString(Map.of("input", inputPayload));
            OpaTransportResponse resp = transport.postDataQuery(pinnedInstanceId, path, body);
            if (resp.statusCode() != 200) {
                throw new OpaEvaluationFailureException(
                        "AUTHZ_OPA_HTTP_STATUS_" + resp.statusCode(),
                        decisionPointKey,
                        "OPA returned non-200 HTTP status " + resp.statusCode() + " on " + path + " (P03)");
            }
            return resp;
        } catch (OpaEvaluationFailureException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_SERIALIZATION_ERROR",
                    decisionPointKey,
                    "Failed to serialize/execute OPA request on " + path + ": " + ex.getMessage(),
                    ex);
        }
    }

    private JsonNode extractRequiredResultNode(
            OpaTransportResponse response,
            String decisionPointKey,
            String expectedSchemaVersion
    ) {
        try {
            JsonNode root = objectMapper.readTree(response.rawJsonBody());
            if (root == null || !root.hasNonNull("result")) {
                // P03: Missing or null "result" key in OPA response MUST fail closed as technical error!
                throw new OpaEvaluationFailureException(
                        "AUTHZ_OPA_UNDEFINED_RESULT",
                        decisionPointKey,
                        "OPA response is missing 'result' field (undefined Rego evaluation) for '"
                                + decisionPointKey + "' (P03 / OPA-IO-002)");
            }
            JsonNode resultNode = root.get("result");
            if (expectedSchemaVersion != null) {
                String actualSchema = resultNode.path("schemaVersion").asText("");
                if (!expectedSchemaVersion.equals(actualSchema)) {
                    throw new OpaEvaluationFailureException(
                            "AUTHZ_OPA_INVALID_RESULT_SCHEMA",
                            decisionPointKey,
                            "Expected OPA result schema '" + expectedSchemaVersion + "' but received '"
                                    + actualSchema + "' (P03 / OPA-IO-001)");
                }
            }
            return resultNode;
        } catch (OpaEvaluationFailureException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_MALFORMED_JSON",
                    decisionPointKey,
                    "Malformed JSON in OPA response for '" + decisionPointKey + "' (P03)",
                    ex);
        }
    }

    private ProviderEvaluationEnvelope buildProviderEnvelope(
            JsonNode resultNode,
            String decisionPointKey,
            EvaluationMode mode,
            long latencyMicros,
            Instant evaluatedAt
    ) {
        try {
            OpaRuntimeHead head = parseRuntimeHead(resultNode.get("runtimeHead"), decisionPointKey, null);
            String factContractDigest = resultNode.path("factContractDigest").asText("");
            List<PolicyUnitContributionTrace> traces = objectMapper.convertValue(
                    resultNode.path("unitContributions"), TRACE_LIST_TYPE);
            List<FieldUseEffectDirective> fieldUse = objectMapper.convertValue(
                    resultNode.path("fieldUseDirectives"), FIELD_USE_LIST_TYPE);
            List<FieldWriteEffectDirective> fieldWrite = objectMapper.convertValue(
                    resultNode.path("fieldWriteDirectives"), FIELD_WRITE_LIST_TYPE);
            List<MaskDirective> masks = objectMapper.convertValue(
                    resultNode.path("maskDirectives"), MASK_LIST_TYPE);
            List<ObligationDirective> obligations = objectMapper.convertValue(
                    resultNode.path("obligationDirectives"), OBLIGATION_LIST_TYPE);

            GateOutcome gateOutcome = combineGateOutcome(traces == null ? List.of() : traces);

            return new ProviderEvaluationEnvelope(
                    ProviderEvaluationEnvelope.SCHEMA_VERSION_V1,
                    "OPA_REGO_V1",
                    "eval-" + UUID.randomUUID(),
                    decisionPointKey,
                    mode,
                    OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                    head.runtimeRevision(),
                    head.policySetDigest(),
                    factContractDigest,
                    gateOutcome,
                    fieldUse == null ? List.of() : fieldUse,
                    fieldWrite == null ? List.of() : fieldWrite,
                    masks == null ? List.of() : masks,
                    obligations == null ? List.of() : obligations,
                    List.of(),
                    traces == null ? List.of() : traces,
                    List.of(),
                    evaluatedAt != null ? evaluatedAt : Instant.now(),
                    latencyMicros
            );
        } catch (Exception ex) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_ENVELOPE_MAPPING_ERROR",
                    decisionPointKey,
                    "Failed to map OPA result into ProviderEvaluationEnvelope: " + ex.getMessage(),
                    ex);
        }
    }

    /**
     * Combines unit contributions according to {@code praxis.authorization-combining/v1} ({@code CC12}):
     * any {@code RESTRICTION} or {@code GRANT} with {@code DENY} dominates {@code ALLOW}; if no
     * contribution matches, returns {@code NOT_APPLICABLE}.
     */
    private static GateOutcome combineGateOutcome(List<PolicyUnitContributionTrace> traces) {
        if (traces.isEmpty()) {
            return GateOutcome.NOT_APPLICABLE;
        }
        boolean anyDeny = false;
        boolean anyGrantAllow = false;
        for (PolicyUnitContributionTrace t : traces) {
            if (t.accessEffect() == RuleEffect.DENY) {
                anyDeny = true;
            } else if (t.accessEffect() == RuleEffect.ALLOW && t.authority() == ContributionAuthority.GRANT) {
                anyGrantAllow = true;
            }
        }
        if (anyDeny) {
            return GateOutcome.DENY;
        }
        if (anyGrantAllow) {
            return GateOutcome.ALLOW;
        }
        return GateOutcome.NOT_APPLICABLE;
    }

    private OpaRuntimeHead parseRuntimeHead(
            JsonNode headNode,
            String decisionPointKey,
            String transportReportedInstanceId
    ) {
        if (headNode == null || headNode.isNull() || headNode.isMissingNode()) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_MISSING_RUNTIME_HEAD",
                    decisionPointKey,
                    "OPA result is missing 'runtimeHead' (P03 / CC11)");
        }
        try {
            OpaRuntimeHead parsed = objectMapper.treeToValue(headNode, OpaRuntimeHead.class);
            if (transportReportedInstanceId != null
                    && !transportReportedInstanceId.isBlank()
                    && !transportReportedInstanceId.equals(parsed.instanceId())) {
                return new OpaRuntimeHead(
                        transportReportedInstanceId,
                        parsed.runtimeRevision(),
                        parsed.headEtag(),
                        parsed.activationRevision(),
                        parsed.policySetDigest(),
                        parsed.bundleArtifactDigest(),
                        parsed.compilerProfileVersion(),
                        parsed.opaCapabilitiesDigest()
                );
            }
            return parsed;
        } catch (Exception ex) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_INVALID_RUNTIME_HEAD",
                    decisionPointKey,
                    "Invalid OpaRuntimeHead in OPA response: " + ex.getMessage(),
                    ex);
        }
    }

    private DataScopePlan parseDataScopePlan(JsonNode planNode, String decisionPointKey) {
        if (planNode == null || planNode.isNull() || planNode.isMissingNode() || !planNode.isObject()) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_MISSING_DATA_SCOPE_PLAN",
                    decisionPointKey,
                    "OPA UCAST result is missing or non-object 'dataScopePlan' (P03 / P24)");
        }
        try {
            String format = planNode.path("format").asText("");
            String planId = planNode.path("planId").asText("");
            String dpKey = planNode.path("decisionPointKey").asText("");
            String resourceKey = planNode.path("resourceKey").asText("");
            String runtimeRevision = planNode.path("runtimeRevision").asText("");
            String policySetDigest = planNode.path("policySetDigest").asText("");
            String factContractDigest = planNode.path("factContractDigest").asText("");
            String queryProjectionRef = planNode.path("queryProjectionRef").asText("");
            String queryProjectionDigest = planNode.path("queryProjectionDigest").asText("");
            DataScopeOutcome scopeOutcome = DataScopeOutcome.valueOf(planNode.path("scopeOutcome").asText(""));
            PushdownMode pushdownMode = PushdownMode.valueOf(planNode.path("pushdownMode").asText(""));
            JsonNode predicateNode = planNode.get("predicateIr");
            SearchPredicateIr predicateIr = (predicateNode == null || predicateNode.isNull())
                    ? null
                    : parseSearchPredicateIr(predicateNode);
            return new DataScopePlan(
                    format,
                    planId,
                    dpKey,
                    resourceKey,
                    runtimeRevision,
                    policySetDigest,
                    factContractDigest,
                    queryProjectionRef,
                    queryProjectionDigest,
                    scopeOutcome,
                    pushdownMode,
                    predicateIr
            );
        } catch (Exception ex) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_INVALID_DATA_SCOPE_PLAN",
                    decisionPointKey,
                    "Invalid DataScopePlan in OPA response: " + ex.getMessage() + " (P24)",
                    ex);
        }
    }

    private SearchPredicateIr parseSearchPredicateIr(JsonNode node) {
        if (node == null || !node.isObject() || !node.hasNonNull("operator")) {
            throw new IllegalArgumentException("Predicate IR node must be an object with 'operator' (P24)");
        }
        SearchPredicateOperator op = SearchPredicateOperator.valueOf(node.get("operator").asText());
        return switch (op) {
            case AND, OR, NOT -> {
                JsonNode operandsNode = node.get("operands");
                if (operandsNode == null || !operandsNode.isArray()) {
                    throw new IllegalArgumentException("Logical operator " + op + " requires array 'operands' (P24)");
                }
                List<SearchPredicateIr> children = new ArrayList<>();
                for (JsonNode child : operandsNode) {
                    children.add(parseSearchPredicateIr(child));
                }
                yield new LogicalPredicateIr(op, children);
            }
            case IS_NULL, IS_NOT_NULL -> new NullabilityPredicateIr(
                    op,
                    node.path("fieldPath").asText(""),
                    node.path("attributeId").asText("")
            );
            default -> {
                String vtRaw = node.hasNonNull("valueType")
                        ? node.path("valueType").asText("")
                        : node.path("fieldValueType").asText("");
                FactValueType valueType = FactValueType.valueOf(vtRaw);
                RightOperandIr rightOp = parseRightOperandIr(node.get("rightOperand"), valueType);
                boolean ci = node.path("caseInsensitive").asBoolean(false);
                yield new ComparisonPredicateIr(
                        op,
                        node.path("fieldPath").asText(""),
                        node.path("attributeId").asText(""),
                        valueType,
                        rightOp,
                        ci
                );
            }
        };
    }

    private RightOperandIr parseRightOperandIr(JsonNode node, FactValueType valueType) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("RightOperandIr must be an object (P24)");
        }
        if (node.hasNonNull("targetFieldPath") && node.hasNonNull("targetAttributeId")) {
            return new FieldRefOperandIr(
                    node.get("targetFieldPath").asText(),
                    node.get("targetAttributeId").asText()
            );
        }
        if (node.hasNonNull("values") && node.get("values").isArray()) {
            List<Object> values = new ArrayList<>();
            for (JsonNode elem : node.get("values")) {
                values.add(extractScalarValue(elem, valueType));
            }
            return new LiteralListOperandIr(values);
        }
        if (node.hasNonNull("value")) {
            return new LiteralOperandIr(extractScalarValue(node.get("value"), valueType));
        }
        throw new IllegalArgumentException("Ambiguous or unsupported RightOperandIr shape (P24)");
    }

    private Object extractScalarValue(JsonNode scalarNode, FactValueType valueType) {
        if (scalarNode == null || scalarNode.isNull()) {
            throw new IllegalArgumentException("Scalar operand value must not be null (P24)");
        }
        return switch (valueType) {
            case INT64 -> scalarNode.asLong();
            case DECIMAL -> scalarNode.decimalValue();
            case BOOLEAN -> scalarNode.asBoolean();
            default -> scalarNode.asText();
        };
    }

    private static Map<String, Object> buildOpaInputEnvelope(
            String schemaVersion,
            String decisionPointKey,
            ProviderInputProjection projection,
            WriteIntent writeIntent
    ) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("decisionPointKey", decisionPointKey);
        map.put("evaluationMode", projection.evaluationMode());
        map.put("factContractDigest", projection.factContractDigest());
        map.put("temporal", projection.temporalContext());
        map.put("projectedInput", projection.projectedInput());
        map.put("projectedFactStatuses", projection.projectedFactStatuses());
        map.put("omittedSensitiveFactPaths", projection.omittedSensitiveFactPaths());
        if (writeIntent != null) {
            map.put("writeIntent", writeIntent);
        }
        return map;
    }

    private static String extractDecisionPointKey(ProviderInputProjection projection) {
        return projection.decisionPointKey();
    }
}
