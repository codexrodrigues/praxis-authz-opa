package org.praxisplatform.authz.opa.governance;

import java.util.Objects;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;

/**
 * Independent positive or negative verification corpus test case executed against a compiled
 * {@code OpaBundleArtifact} before approval and activation ({@code P53}, {@code P63}).
 *
 * <p>Per {@code MATRIZ-INTEGRACAO-E-GATES.md} ({@code P53}, {@code P63}), every governed release
 * requires both positive ({@code ALLOW} / {@code FILTER}) and negative ({@code DENY} / {@code NOT_APPLICABLE} / {@code NONE})
 * cases — {@code denyAll} alone or zero corpus cases is rejected fail-closed.</p>
 *
 * @param caseId unique test case identifier
 * @param description human-readable scenario description
 * @param evaluationMode evaluation mode ({@code TARGET} or {@code SEARCH})
 * @param inputProjection minimized provider input projection
 * @param writeIntent optional write intent for {@code TARGET} mutations
 * @param expectedGateOutcome expected gate outcome ({@code ALLOW}, {@code DENY}, {@code NOT_APPLICABLE})
 * @param expectedReasonCode optional expected reason code
 * @param expectedDataScopeOutcome optional expected data scope outcome for {@code SEARCH} cases
 */
public record PolicyCandidateVerificationCorpusCase(
        String caseId,
        String description,
        EvaluationMode evaluationMode,
        ProviderInputProjection inputProjection,
        WriteIntent writeIntent,
        GateOutcome expectedGateOutcome,
        String expectedReasonCode,
        DataScopeOutcome expectedDataScopeOutcome
) {

    /** Validates required corpus case fields. */
    public PolicyCandidateVerificationCorpusCase {
        caseId = requireNonBlank(caseId, "caseId");
        description = requireNonBlank(description, "description");
        evaluationMode = Objects.requireNonNull(evaluationMode, "evaluationMode is required");
        inputProjection = Objects.requireNonNull(inputProjection, "inputProjection is required");
        expectedGateOutcome = Objects.requireNonNull(expectedGateOutcome, "expectedGateOutcome is required");
    }

    /** Returns {@code true} when this corpus case proves a permitted capability (anti-denyAll gate). */
    public boolean isPositiveCase() {
        return expectedGateOutcome == GateOutcome.ALLOW;
    }

    private static String requireNonBlank(String value, String field) {
        Objects.requireNonNull(value, field + " is required");
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return trimmed;
    }
}
