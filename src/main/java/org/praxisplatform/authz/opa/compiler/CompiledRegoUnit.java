package org.praxisplatform.authz.opa.compiler;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.praxisplatform.authz.contracts.digest.OpaPolicyUnitManifest;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.contracts.policy.FieldResolutionManifest;
import org.praxisplatform.authz.contracts.policy.TargetResolutionManifest;

/**
 * Immutable output of compiling a single validated {@link AuthorizationPolicyDefinition} into a
 * Rego v1 module ({@code CC01}, {@code CC02}, {@code CC11}, {@code OPA-GEN-001}, {@code P53}, {@code P63}).
 *
 * @param unitManifest Level-1 OPA policy unit manifest containing the 5-stage {@code PolicyDigestChain}
 * @param moduleFilePath path of the generated {@code .rego} file inside the OPA bundle archive
 * @param regoSource deterministic Rego v1 source code ({@code import rego.v1})
 * @param sourcePolicy source policy definition
 * @param resolvedTargets frozen target resolution manifests
 * @param resolvedFieldSelectors frozen field selector resolution manifests keyed by selector digest
 */
public record CompiledRegoUnit(
        OpaPolicyUnitManifest unitManifest,
        String moduleFilePath,
        String regoSource,
        AuthorizationPolicyDefinition sourcePolicy,
        List<TargetResolutionManifest> resolvedTargets,
        Map<String, FieldResolutionManifest> resolvedFieldSelectors
) {

    /** Validates non-null fields and Rego v1 header compliance. */
    public CompiledRegoUnit {
        unitManifest = Objects.requireNonNull(unitManifest, "unitManifest is required");
        Objects.requireNonNull(moduleFilePath, "moduleFilePath is required");
        moduleFilePath = moduleFilePath.trim();
        if (moduleFilePath.isEmpty() || !moduleFilePath.endsWith(".rego")) {
            throw new IllegalArgumentException("moduleFilePath must be a non-blank .rego path: " + moduleFilePath);
        }
        Objects.requireNonNull(regoSource, "regoSource is required");
        if (!regoSource.contains("import rego.v1")) {
            throw new IllegalArgumentException("Compiled Rego module must declare 'import rego.v1' (OPA-CMP-001)");
        }
        sourcePolicy = Objects.requireNonNull(sourcePolicy, "sourcePolicy is required");
        resolvedTargets = resolvedTargets == null ? List.of() : List.copyOf(resolvedTargets);
        resolvedFieldSelectors = resolvedFieldSelectors == null ? Map.of() : Map.copyOf(resolvedFieldSelectors);
    }
}
