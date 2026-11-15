package org.praxisplatform.authz.opa.revision;

import java.util.Objects;

/**
 * Thrown when an OPA evaluation fails technically — such as an HTTP timeout, non-200 status,
 * missing {@code result} key (undefined Rego evaluation), schema mismatch, or mid-flight revision
 * drift ({@code P03}, {@code P17}, {@code P18}, {@code OPA-IO-001..004}).
 *
 * <p>Per {@code P03}, technical provider errors are distinguishable from valid policy denials via
 * {@link #getErrorCode()} while always failing closed (never granting access).</p>
 */
public class OpaEvaluationFailureException extends RuntimeException {

    private final String errorCode;
    private final String decisionPointKey;

    /**
     * Constructs a technical OPA evaluation failure exception.
     *
     * @param errorCode canonical diagnostic error code (e.g. {@code AUTHZ_OPA_UNDEFINED_RESULT}, {@code AUTHZ_OPA_TIMEOUT})
     * @param decisionPointKey canonical decision point key being evaluated
     * @param message descriptive diagnostic message
     */
    public OpaEvaluationFailureException(String errorCode, String decisionPointKey, String message) {
        super(message);
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode is required");
        this.decisionPointKey = Objects.requireNonNull(decisionPointKey, "decisionPointKey is required");
    }

    /**
     * Constructs a technical OPA evaluation failure exception with a root cause.
     */
    public OpaEvaluationFailureException(String errorCode, String decisionPointKey, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode is required");
        this.decisionPointKey = Objects.requireNonNull(decisionPointKey, "decisionPointKey is required");
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getDecisionPointKey() {
        return decisionPointKey;
    }
}
