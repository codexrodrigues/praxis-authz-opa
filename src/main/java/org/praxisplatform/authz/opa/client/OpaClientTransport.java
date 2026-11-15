package org.praxisplatform.authz.opa.client;

/**
 * Pluggable transport abstraction for querying OPA REST endpoints ({@code /v1/data/praxis/authz/v1/...})
 * with instance-affinity pinning ({@code CC11}, {@code OPA-IO-001..004}, {@code OPA-SEARCH-001..004}).
 */
public interface OpaClientTransport {

    /**
     * Executes a POST query against an OPA data/rule path on the specified (or default) instance.
     *
     * @param pinnedInstanceId optional instance ID to pin the request to (required for steps 2 and 3 of {@code SEARCH})
     * @param opaDataPath OPA REST path (e.g. {@code /v1/data/praxis/authz/v1/evaluate_target})
     * @param requestJsonBody serialized {@code {"input": ...}} JSON payload
     * @return transport response
     */
    OpaTransportResponse postDataQuery(
            String pinnedInstanceId,
            String opaDataPath,
            String requestJsonBody
    );
}
