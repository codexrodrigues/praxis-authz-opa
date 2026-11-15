package org.praxisplatform.authz.opa.governance;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable governance receipt emitted when a candidate policy set passes validation, compilation,
 * independent positive/negative corpus verification, and digest-pinned activation ({@code P28},
 * {@code P32}, {@code P53}, {@code P55}, {@code P63}).
 *
 * @param releaseId unique release identifier
 * @param runtimeRevision activated runtime revision
 * @param activationRevision monotonic activation counter
 * @param approvedByPrincipalId authenticated administrative principal who approved the activation
 * @param approvedDefinitionFingerprintsByPolicyId map of {@code policyId -> definitionFingerprint} verified at activation
 * @param policySetDigest stage 7 policy set digest
 * @param bundleArtifactDigest stage 8 bundle artifact digest
 * @param positiveCorpusCasesPassed number of positive {@code ALLOW} corpus cases verified (> 0)
 * @param negativeCorpusCasesPassed number of negative {@code DENY}/{@code NOT_APPLICABLE} corpus cases verified (> 0)
 * @param activatedAt activation timestamp
 */
public record PolicyCandidateActivationReceipt(
        String releaseId,
        String runtimeRevision,
        long activationRevision,
        String approvedByPrincipalId,
        Map<String, String> approvedDefinitionFingerprintsByPolicyId,
        String policySetDigest,
        String bundleArtifactDigest,
        int positiveCorpusCasesPassed,
        int negativeCorpusCasesPassed,
        Instant activatedAt
) {

    /** Validates non-blank fields and positive/negative corpus counts ({@code P63} anti-denyAll gate). */
    public PolicyCandidateActivationReceipt {
        Objects.requireNonNull(releaseId, "releaseId is required");
        Objects.requireNonNull(runtimeRevision, "runtimeRevision is required");
        if (activationRevision < 1) {
            throw new IllegalArgumentException("activationRevision must be >= 1");
        }
        Objects.requireNonNull(approvedByPrincipalId, "approvedByPrincipalId is required");
        Objects.requireNonNull(approvedDefinitionFingerprintsByPolicyId, "approvedDefinitionFingerprintsByPolicyId is required");
        approvedDefinitionFingerprintsByPolicyId = Map.copyOf(approvedDefinitionFingerprintsByPolicyId);
        Objects.requireNonNull(policySetDigest, "policySetDigest is required");
        Objects.requireNonNull(bundleArtifactDigest, "bundleArtifactDigest is required");
        if (positiveCorpusCasesPassed < 1 || negativeCorpusCasesPassed < 1) {
            throw new IllegalArgumentException(
                    "Governed activation requires at least 1 positive and 1 negative corpus case (P53 / P63)");
        }
        activatedAt = Objects.requireNonNull(activatedAt, "activatedAt is required");
    }
}
