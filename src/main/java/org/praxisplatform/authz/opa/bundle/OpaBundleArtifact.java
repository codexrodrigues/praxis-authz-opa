package org.praxisplatform.authz.opa.bundle;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeRelease;
import org.praxisplatform.authz.opa.compiler.CompiledRegoUnit;

/**
 * Immutable materialized OPA bundle artifact linking the 4-level lineage ({@code Unit -> Composition -> PolicySet -> Release})
 * to the deterministic Rego v1 modules, {@code data.json}, and gzipped archive bytes ({@code CC11}, {@code OPA-GEN-001..004}).
 *
 * @param runtimeRelease Level-4 runtime release descriptor
 * @param runtimeHead runtime head served at {@code /v1/data/praxis/authz/v1/runtime_head}
 * @param dataDocument structured {@code data.json} payload
 * @param systemCombiningRegoSource source code of {@code praxis/authz/system/combining.rego}
 * @param compiledUnits compiled Rego v1 policy units included in this bundle
 * @param bundleFilesByPath deterministic map of bundle archive file paths to UTF-8 text contents
 * @param bundleArchiveBytes deterministic gzipped bundle archive bytes hashed by {@code bundleArtifactDigest}
 */
public record OpaBundleArtifact(
        OpaRuntimeRelease runtimeRelease,
        OpaRuntimeHead runtimeHead,
        OpaBundleDataDocument dataDocument,
        String systemCombiningRegoSource,
        List<CompiledRegoUnit> compiledUnits,
        Map<String, String> bundleFilesByPath,
        byte[] bundleArchiveBytes
) {

    /** Validates non-null bundle components and clones archive bytes defensively. */
    public OpaBundleArtifact {
        runtimeRelease = Objects.requireNonNull(runtimeRelease, "runtimeRelease is required");
        runtimeHead = Objects.requireNonNull(runtimeHead, "runtimeHead is required");
        dataDocument = Objects.requireNonNull(dataDocument, "dataDocument is required");
        systemCombiningRegoSource = Objects.requireNonNull(systemCombiningRegoSource, "systemCombiningRegoSource is required");
        Objects.requireNonNull(compiledUnits, "compiledUnits is required");
        if (compiledUnits.isEmpty()) {
            throw new IllegalArgumentException("compiledUnits must not be empty");
        }
        compiledUnits = List.copyOf(compiledUnits);
        Objects.requireNonNull(bundleFilesByPath, "bundleFilesByPath is required");
        bundleFilesByPath = Map.copyOf(bundleFilesByPath);
        bundleArchiveBytes = Objects.requireNonNull(bundleArchiveBytes, "bundleArchiveBytes is required").clone();
    }

    @Override
    public byte[] bundleArchiveBytes() {
        return bundleArchiveBytes.clone();
    }
}
