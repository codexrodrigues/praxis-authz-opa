package org.praxisplatform.authz.opa.bundle;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.GZIPOutputStream;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.digest.OpaPolicyUnitManifest;
import org.praxisplatform.authz.contracts.digest.OpaProviderIoSchemas;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeCompositionManifest;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeRelease;
import org.praxisplatform.authz.contracts.digest.PolicySetContent;
import org.praxisplatform.authz.opa.compiler.CompiledRegoUnit;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;

/**
 * Assembles a deterministic {@link OpaBundleArtifact} across all 4 OPA runtime lineage levels and
 * all 8 acyclic digest domains, rejecting competing authoritative policy units ({@code CC11},
 * {@code BND-DIG-001..003}, {@code OPA-GEN-001..004}, {@code P38}, {@code P55}).
 */
public final class OpaBundleAssembler {

    private final RegoV1PolicyCompiler compiler;
    private final ObjectMapper objectMapper;

    /** Constructs a bundle assembler with a default {@link RegoV1PolicyCompiler}. */
    public OpaBundleAssembler() {
        this(new RegoV1PolicyCompiler());
    }

    /**
     * Constructs a bundle assembler with the given compiler.
     *
     * @param compiler Rego v1 policy compiler
     */
    public OpaBundleAssembler(RegoV1PolicyCompiler compiler) {
        this.compiler = Objects.requireNonNull(compiler, "compiler is required");
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    /**
     * Assembles a complete {@link OpaBundleArtifact} from the compiled Rego v1 units, verifying
     * that no two units dispute the same {@code policyUnitKey} or {@code policyId} ({@code P38}).
     *
     * @param releaseId unique release identifier
     * @param runtimeRevision operational runtime revision identifier
     * @param activationRevision monotonic activation counter (positive)
     * @param environmentKey target environment key
     * @param instanceId initial serving OPA instance identifier
     * @param opaCapabilitiesDigest target OPA capabilities profile digest
     * @param compiledUnits non-empty collection of compiled Rego v1 units
     * @return deterministic {@link OpaBundleArtifact}
     */
    public OpaBundleArtifact assembleBundle(
            String releaseId,
            String runtimeRevision,
            long activationRevision,
            String environmentKey,
            String instanceId,
            String opaCapabilitiesDigest,
            Collection<CompiledRegoUnit> compiledUnits
    ) {
        Objects.requireNonNull(releaseId, "releaseId is required");
        Objects.requireNonNull(runtimeRevision, "runtimeRevision is required");
        Objects.requireNonNull(environmentKey, "environmentKey is required");
        Objects.requireNonNull(instanceId, "instanceId is required");
        Objects.requireNonNull(opaCapabilitiesDigest, "opaCapabilitiesDigest is required");
        Objects.requireNonNull(compiledUnits, "compiledUnits is required");
        if (compiledUnits.isEmpty()) {
            throw new IllegalArgumentException("compiledUnits must not be empty");
        }

        // P38 & BND-DIG-001: Reject competing units claiming the same policyUnitKey or policyId,
        // and sort canonically by policyUnitKey so bundle assembly is 100% order-independent.
        Set<String> seenUnitKeys = new LinkedHashSet<>();
        Set<String> seenPolicyIds = new LinkedHashSet<>();
        List<CompiledRegoUnit> orderedUnits = new ArrayList<>(compiledUnits);
        for (CompiledRegoUnit unit : orderedUnits) {
            String unitKey = unit.unitManifest().policyUnitKey();
            String policyId = unit.unitManifest().policyId();
            if (!seenUnitKeys.add(unitKey)) {
                throw new IllegalArgumentException(
                        "Competing authoritative policyUnitKey detected in bundle composition: '"
                                + unitKey + "' (P38 / PCB-UNIT-002)");
            }
            if (!seenPolicyIds.add(policyId)) {
                throw new IllegalArgumentException(
                        "Competing policy definitions for policyId '" + policyId
                                + "' detected in bundle composition (P38 / PCB-UNIT-002)");
            }
        }
        orderedUnits.sort((a, b) -> a.unitManifest().policyUnitKey().compareTo(b.unitManifest().policyUnitKey()));

        List<OpaPolicyUnitManifest> unitManifests = new ArrayList<>();
        TreeMap<String, List<String>> unitKeysByDecisionPointKey = new TreeMap<>();

        for (CompiledRegoUnit unit : orderedUnits) {
            String unitKey = unit.unitManifest().policyUnitKey();
            unitManifests.add(unit.unitManifest());
            List<String> sortedPointKeys = new ArrayList<>(unit.unitManifest().targetPointKeys());
            sortedPointKeys.sort(String::compareTo);
            for (String dpKey : sortedPointKeys) {
                unitKeysByDecisionPointKey
                        .computeIfAbsent(dpKey, k -> new ArrayList<>())
                        .add(unitKey);
            }
        }

        String systemCombiningRego = compiler.generateSystemCombiningModuleSource(orderedUnits);
        String systemCombiningDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.GENERATED_ARTIFACT_DIGEST, systemCombiningRego);

        // Stage 6: COMPOSITION_DIGEST
        StringBuilder compPreimage = new StringBuilder(systemCombiningDigest);
        for (OpaPolicyUnitManifest um : unitManifests) {
            compPreimage.append('|').append(um.policyUnitKey()).append(':')
                    .append(um.digestChain().materializationFingerprint());
        }
        String stage6CompositionDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.COMPOSITION_DIGEST, compPreimage.toString());

        OpaRuntimeCompositionManifest compositionManifest = new OpaRuntimeCompositionManifest(
                "comp-" + runtimeRevision,
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                systemCombiningDigest,
                unitManifests,
                stage6CompositionDigest
        );

        // Stage 7: POLICY_SET_DIGEST
        String stage7PolicySetDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.POLICY_SET_DIGEST,
                environmentKey + "|" + stage6CompositionDigest);
        PolicySetContent policySetContent = new PolicySetContent(
                "pset-" + runtimeRevision,
                environmentKey,
                stage6CompositionDigest,
                stage7PolicySetDigest
        );

        // Build deterministic file map in sorted order before computing Stage 8 BUNDLE_ARTIFACT_DIGEST
        TreeMap<String, String> sortedFiles = new TreeMap<>();
        sortedFiles.put(RegoV1PolicyCompiler.SYSTEM_COMBINING_MODULE_PATH, systemCombiningRego);
        for (CompiledRegoUnit unit : orderedUnits) {
            sortedFiles.put(unit.moduleFilePath(), unit.regoSource());
        }
        String manifestJson = "{\"revision\":\"" + runtimeRevision
                + "\",\"roots\":[\"praxis/authz\"],\"rego_version\":1}";
        sortedFiles.put(".manifest", manifestJson);

        Map<String, List<String>> immutableIndex = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : unitKeysByDecisionPointKey.entrySet()) {
            immutableIndex.put(e.getKey(), List.copyOf(e.getValue()));
        }

        String headEtag = "W/\"" + runtimeRevision + "-" + activationRevision + "\"";
        StringBuilder archivePreimage = new StringBuilder(policySetContent.policySetDigest())
                .append('|').append(runtimeRevision)
                .append('|').append(headEtag)
                .append('|').append(activationRevision)
                .append('|').append(opaCapabilitiesDigest)
                .append('|').append(immutableIndex);
        for (Map.Entry<String, String> entry : sortedFiles.entrySet()) {
            archivePreimage.append('|').append(entry.getKey()).append(':').append(entry.getValue());
        }
        String stage8BundleDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.BUNDLE_ARTIFACT_DIGEST, archivePreimage.toString());

        OpaRuntimeRelease runtimeRelease = new OpaRuntimeRelease(
                releaseId,
                runtimeRevision,
                headEtag,
                activationRevision,
                stage7PolicySetDigest,
                stage8BundleDigest,
                OpaProviderIoSchemas.COMPILER_PROFILE_V1,
                compositionManifest
        );

        OpaRuntimeHead runtimeHead = new OpaRuntimeHead(
                instanceId,
                runtimeRevision,
                headEtag,
                activationRevision,
                stage7PolicySetDigest,
                stage8BundleDigest,
                OpaProviderIoSchemas.COMPILER_PROFILE_V1,
                opaCapabilitiesDigest
        );

        OpaBundleDataDocument dataDocument = new OpaBundleDataDocument(
                runtimeHead,
                runtimeRelease,
                immutableIndex
        );
        try {
            sortedFiles.put("praxis/authz/data.json", objectMapper.writeValueAsString(dataDocument));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to serialize OpaBundleDataDocument", ex);
        }

        byte[] archiveBytes = compressDeterministicArchive(sortedFiles);
        return new OpaBundleArtifact(
                runtimeRelease,
                runtimeHead,
                dataDocument,
                systemCombiningRego,
                orderedUnits,
                sortedFiles,
                archiveBytes
        );
    }

    private static byte[] compressDeterministicArchive(Map<String, String> sortedFiles) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            for (Map.Entry<String, String> entry : sortedFiles.entrySet()) {
                String header = "FILE:" + entry.getKey() + "\n";
                gzip.write(header.getBytes(StandardCharsets.UTF_8));
                gzip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                gzip.write("\n---END-FILE---\n".getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to compress OPA bundle archive", ex);
        }
        return baos.toByteArray();
    }
}
