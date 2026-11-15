package org.praxisplatform.authz.opa.client;

import java.util.Objects;

/**
 * Raw response returned by an {@link OpaClientTransport} call ({@code CC11}, {@code P03}).
 *
 * @param statusCode HTTP status code (e.g. {@code 200})
 * @param instanceId serving OPA instance identifier
 * @param rawJsonBody raw JSON response body containing {@code {"result": ...}}
 * @param latencyMicros measured call latency in microseconds
 */
public record OpaTransportResponse(
        int statusCode,
        String instanceId,
        String rawJsonBody,
        long latencyMicros
) {

    /** Validates non-null fields and non-negative latency. */
    public OpaTransportResponse {
        Objects.requireNonNull(instanceId, "instanceId is required");
        Objects.requireNonNull(rawJsonBody, "rawJsonBody is required");
        if (latencyMicros < 0) {
            throw new IllegalArgumentException("latencyMicros must be >= 0");
        }
    }
}
