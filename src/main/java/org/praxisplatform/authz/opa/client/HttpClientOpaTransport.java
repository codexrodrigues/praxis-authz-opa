package org.praxisplatform.authz.opa.client;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import org.praxisplatform.authz.opa.revision.OpaEvaluationFailureException;

/**
 * Production {@link HttpClient}-backed implementation of {@link OpaClientTransport} supporting
 * instance-affinity URI routing and strict fail-closed timeout/status handling ({@code CC11}, {@code P03}, {@code P17}).
 */
public final class HttpClientOpaTransport implements OpaClientTransport {

    private final String defaultInstanceId;
    private final Map<String, URI> baseUriByInstanceId;
    private final HttpClient httpClient;
    private final Duration requestTimeout;

    /**
     * Constructs an HTTP OPA transport with a map of instance IDs to base URIs and a strict request timeout.
     */
    public HttpClientOpaTransport(
            String defaultInstanceId,
            Map<String, URI> baseUriByInstanceId,
            Duration requestTimeout
    ) {
        this.defaultInstanceId = Objects.requireNonNull(defaultInstanceId, "defaultInstanceId is required");
        Objects.requireNonNull(baseUriByInstanceId, "baseUriByInstanceId is required");
        if (!baseUriByInstanceId.containsKey(defaultInstanceId)) {
            throw new IllegalArgumentException("baseUriByInstanceId must contain defaultInstanceId: " + defaultInstanceId);
        }
        this.baseUriByInstanceId = Map.copyOf(baseUriByInstanceId);
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout is required");
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(requestTimeout)
                .build();
    }

    @Override
    public OpaTransportResponse postDataQuery(
            String pinnedInstanceId,
            String opaDataPath,
            String requestJsonBody
    ) {
        Objects.requireNonNull(opaDataPath, "opaDataPath is required");
        Objects.requireNonNull(requestJsonBody, "requestJsonBody is required");

        String targetInstanceId = (pinnedInstanceId == null || pinnedInstanceId.isBlank())
                ? defaultInstanceId
                : pinnedInstanceId;
        URI baseUri = baseUriByInstanceId.get(targetInstanceId);
        if (baseUri == null) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_UNKNOWN_INSTANCE",
                    opaDataPath,
                    "Unknown pinned OPA instanceId '" + targetInstanceId + "' (P17 / OPA-SEARCH-004)");
        }

        URI endpointUri = baseUri.resolve(opaDataPath);
        HttpRequest request = HttpRequest.newBuilder(endpointUri)
                .timeout(requestTimeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestJsonBody))
                .build();

        long startNanos = System.nanoTime();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            long elapsedMicros = Math.max(1L, (System.nanoTime() - startNanos) / 1_000L);
            String reportedInstance = response.headers()
                    .firstValue("X-OPA-Instance-Id")
                    .orElse(targetInstanceId);
            return new OpaTransportResponse(
                    response.statusCode(),
                    reportedInstance,
                    response.body() == null ? "" : response.body(),
                    elapsedMicros
            );
        } catch (HttpTimeoutException ex) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_TIMEOUT",
                    opaDataPath,
                    "OPA HTTP query timed out after " + requestTimeout.toMillis() + " ms on " + endpointUri + " (P03)",
                    ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_INTERRUPTED",
                    opaDataPath,
                    "OPA HTTP query interrupted on " + endpointUri + " (P03)",
                    ex);
        } catch (IOException ex) {
            throw new OpaEvaluationFailureException(
                    "AUTHZ_OPA_IO_ERROR",
                    opaDataPath,
                    "OPA HTTP I/O failure on " + endpointUri + ": " + ex.getMessage() + " (P03)",
                    ex);
        }
    }
}
