package org.praxisplatform.authz.opa.revision;

import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;

/**
 * Thrown when the 3-step {@code SEARCH} same-instance revision guard ({@code preflight -> compile -> postflight})
 * detects an OPA instance switch or bundle revision drift across steps ({@code CC11}, {@code OPA-SEARCH-001..004},
 * {@code P17}, {@code P18}).
 */
public final class OpaRevisionMismatchException extends OpaEvaluationFailureException {

    private final OpaRuntimeHead preflightHead;
    private final OpaRuntimeHead postflightHead;

    /**
     * Constructs a revision mismatch exception with the conflicting preflight and postflight heads.
     */
    public OpaRevisionMismatchException(
            String decisionPointKey,
            OpaRuntimeHead preflightHead,
            OpaRuntimeHead postflightHead,
            String message
    ) {
        super("AUTHZ_OPA_SEARCH_REVISION_MISMATCH", decisionPointKey, message);
        this.preflightHead = preflightHead;
        this.postflightHead = postflightHead;
    }

    public OpaRuntimeHead getPreflightHead() {
        return preflightHead;
    }

    public OpaRuntimeHead getPostflightHead() {
        return postflightHead;
    }
}
