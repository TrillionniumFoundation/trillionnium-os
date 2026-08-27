// Copyright 2026 The Trillionnium OS Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package receiptstage

import (
	"path/filepath"
	"strings"

	"github.com/google/blueprint"

	"android/soong/android"
)

const (
	stageRoot                = "trillionnium/receipt-stage-v1"
	stageReceipt             = "receipt-stage.v1.json"
	contractPath             = "contracts/trillionnium-receipt-stage-v1.contract.json"
	verifierTool             = "trillionnium-receipt-stage-verify"
	materializerTool         = "trillionnium-receipt-stage-materialize"
	materializerInputRootEnv = "TRILLINNIUM_RECEIPT_STAGE_INPUT_ROOT"
	stageReceiptTag          = ".stage_receipt"
	custodyTag               = ".custody_attestation"
)

type roleSpec struct {
	role           string
	stagePath      string
	outputFilename string
	tag            string
}

// This is deliberately a closed list.  Artifact hashes never appear here;
// they enter the graph only through the self-hashed external stage receipt.
var roleSpecs = []roleSpec{
	{"common_daemon", "artifacts/common/trillionniumd", "common-trillionniumd", ".common_daemon"},
	{"common_codex_launcher", "artifacts/common/trillionnium-codex-agent-0.144.1", "common-codex-launcher", ".common_codex_launcher"},
	{"codex_runtime", "artifacts/common/codex-runtime-0.144.1", "codex-runtime-0.144.1", ".codex_runtime"},
	{"common_system_api", "artifacts/common/trillionnium-agent-system-api", "common-system-api", ".common_system_api"},
	{"common_accessibility", "artifacts/common/trillionnium-agent-accessibility", "common-accessibility", ".common_accessibility"},
	{"common_replay_sync", "artifacts/common/trillionnium-system-api-replay-sync", "common-replay-sync", ".common_replay_sync"},
	{"p01_daemon", "artifacts/p01/trillionniumd", "p01-trillionniumd", ".p01_daemon"},
	{"p01_codex_launcher", "artifacts/p01/trillionnium-codex-agent-0.144.1-p01-userdebug", "p01-codex-launcher", ".p01_codex_launcher"},
	{"p01_system_api", "artifacts/p01/trillionnium-agent-system-api-device-conformance", "p01-system-api", ".p01_system_api"},
	{"p01_replay_sync", "artifacts/p01/trillionnium-system-api-device-conformance-replay-sync", "p01-replay-sync", ".p01_replay_sync"},
	{"p01_high_water", "artifacts/p01/trillionnium-direct-operation-custody-high-water", "p01-high-water", ".p01_high_water"},
	{"p01_shell_tool", "artifacts/p01/trillionnium-agent-shell", "p01-agent-shell", ".p01_shell_tool"},
	{"p01_shell_broker", "artifacts/p01/trillionnium-shell-exec-broker-userdebug", "p01-shell-exec-broker-userdebug", ".p01_shell_broker"},
	{"p01_shell_worker", "artifacts/p01/trillionnium-shell-exec-worker-userdebug", "p01-shell-exec-worker-userdebug", ".p01_shell_worker"},
	{"shell_artifact_set", "evidence/trillionnium-shell-exec-artifact-set-v1.json", "trillionnium-shell-exec-artifact-set-v1.json", ".shell_artifact_set"},
	{"rootfs_archive", "artifacts/rootfs/rootfs-current.tar.zst", "rootfs-current.tar.zst", ".rootfs_archive"},
	{"fresh_base_receipt", "evidence/minimal-bookworm-arm64.receipt.json", "minimal-bookworm-arm64.receipt.json", ".fresh_base_receipt"},
	{"fresh_base_sbom", "evidence/minimal-bookworm-arm64.spdx.json", "minimal-bookworm-arm64.spdx.json", ".fresh_base_sbom"},
	{"source_bom", "evidence/source-bom.v2.json", "source-bom.v2.json", ".source_bom"},
	{"resolved_manifest", "evidence/resolved-manifest.xml", "resolved-manifest.xml", ".resolved_manifest"},
	{"common_artifact_set", "evidence/common-codex-rootfs-artifact-set.v5.json", "common-codex-rootfs-artifact-set.v5.json", ".common_artifact_set"},
	{"p01_final_artifact_set", "evidence/p01-userdebug-final-daemon-artifact-set.v5.json", "p01-userdebug-final-daemon-artifact-set.v5.json", ".p01_final_artifact_set"},
	{"rootfs_contract", "evidence/rootfs-package.contract.v9.json", "rootfs-package.contract.v9.json", ".rootfs_contract"},
	{"rootfs_receipt", "evidence/rootfs-package-receipt.json", "rootfs-package-receipt.json", ".rootfs_receipt"},
	{"p01_runtime_config", "runtime/p01-runtime.env", "p01-runtime.env", ".p01_runtime_config"},
	{"p01_agent_manifest", "runtime/agent-codex-direct-v1.json", "p01-agent-codex-direct-v1.json", ".p01_agent_manifest"},
	{"root_linux_manifest", "runtime/root-linux-manifest.txt", "p01-root-linux-manifest.txt", ".root_linux_manifest"},
}

type verifierDependencyTag struct {
	blueprint.BaseDependencyTag
}

var verifierTag verifierDependencyTag

// The materializer is a separate host tool because it must read the original
// OUT_DIR inputs before the verifier's sbox copy can erase hard-link custody
// metadata.  Keep its dependency tag distinct from verifierTag so the two
// host tools cannot be confused when resolving providers.
type materializerDependencyTag struct {
	blueprint.BaseDependencyTag
}

var materializerTag materializerDependencyTag

type ReceiptStage struct {
	android.ModuleBase
}

func (module *ReceiptStage) DepsMutator(ctx android.BottomUpMutatorContext) {
	ctx.AddFarVariationDependencies(
		ctx.Config().BuildOSTarget.Variations(),
		verifierTag,
		verifierTool,
	)
	if ctx.Config().Getenv(materializerInputRootEnv) != "" {
		ctx.AddFarVariationDependencies(
			ctx.Config().BuildOSTarget.Variations(),
			materializerTag,
			materializerTool,
		)
	}
}

func receiptStageVerifier(ctx android.ModuleContext) android.Path {
	var result android.Path
	ctx.VisitDirectDepsProxyAllowDisabled(func(proxy android.ModuleProxy) {
		dependency := android.PrebuiltGetPreferred(ctx, proxy)
		if ctx.OtherModuleDependencyTag(dependency) != verifierTag {
			return
		}
		provider, ok := android.OtherModuleProvider(
			ctx,
			dependency,
			android.HostToolProviderInfoProvider,
		)
		if !ok {
			ctx.ModuleErrorf("%q is not a host tool provider", verifierTool)
			return
		}
		if !provider.HostToolPath.Valid() {
			ctx.ModuleErrorf("%q has no host tool output", verifierTool)
			return
		}
		if result != nil {
			ctx.ModuleErrorf("multiple %q host tools selected", verifierTool)
			return
		}
		result = provider.HostToolPath.Path()
	})
	if result == nil && !ctx.Failed() {
		ctx.ModuleErrorf("missing %q host verifier dependency", verifierTool)
	}
	return result
}

func receiptStageMaterializer(ctx android.ModuleContext) android.Path {
	var result android.Path
	ctx.VisitDirectDepsProxyAllowDisabled(func(proxy android.ModuleProxy) {
		dependency := android.PrebuiltGetPreferred(ctx, proxy)
		if ctx.OtherModuleDependencyTag(dependency) != materializerTag {
			return
		}
		provider, ok := android.OtherModuleProvider(
			ctx,
			dependency,
			android.HostToolProviderInfoProvider,
		)
		if !ok {
			ctx.ModuleErrorf("%q is not a host tool provider", materializerTool)
			return
		}
		if !provider.HostToolPath.Valid() {
			ctx.ModuleErrorf("%q has no host tool output", materializerTool)
			return
		}
		if result != nil {
			ctx.ModuleErrorf("multiple %q host tools selected", materializerTool)
			return
		}
		result = provider.HostToolPath.Path()
	})
	if result == nil && !ctx.Failed() {
		ctx.ModuleErrorf("missing %q host materializer dependency", materializerTool)
	}
	return result
}

// addReceiptStageMaterializer wires the external stage into Ninja when the
// caller supplies a role-keyed input directory.  Previously the stage paths
// were only PathForArbitraryOutput references, so Ninja had no rule capable of
// producing them and stopped with "missing and no known rule to make it".
//
// The hook is opt-in through an absolute input-root environment variable.  A
// caller must place one regular file named exactly after each of the 24
// physical role names in that directory.  The materializer itself performs
// all mode, link-count, schema, cross-binding, and atomic-publication checks;
// this rule only supplies the dependency edges.  No default build receives an
// implicit external input source.
func addReceiptStageMaterializer(
	ctx android.ModuleContext,
	materializer android.Path,
	contract android.Path,
	baseManifest android.Path,
	stageStamp android.WritablePath,
	allowUserdebugDogfood bool,
) bool {
	inputRoot := ctx.Config().Getenv(materializerInputRootEnv)
	if inputRoot == "" {
		return false
	}
	if !filepath.IsAbs(inputRoot) {
		ctx.ModuleErrorf("%s must be an absolute directory", materializerInputRootEnv)
		return false
	}
	inputRoot = filepath.Clean(inputRoot)
	outDir := filepath.Clean(ctx.Config().OutDir())
	if inputRoot == outDir || strings.HasPrefix(inputRoot, outDir+string(filepath.Separator)) {
		ctx.ModuleErrorf("%s must be outside the Android OUT_DIR", materializerInputRootEnv)
		return false
	}
	stageRoot := filepath.Join(filepath.Dir(stageStamp.String()), "receipt-stage-v1")
	rule := android.NewRuleBuilder(pctx, ctx)
	command := rule.Command().
		Tool(materializer).
		FlagWithInput("--contract=", contract).
		FlagWithInput("--base-root-linux-manifest=", baseManifest).
		FlagWithArg("--stage-root=", stageRoot)
	// The materializer accepts only the physical source set.  The final three
	// roleSpecs are derived runtime files that it creates after validating the
	// physical inputs; passing them as --input arguments makes the CLI reject a
	// valid role directory before it can derive them.
	physicalRoleSpecs := roleSpecs[:len(roleSpecs)-3]
	for _, spec := range physicalRoleSpecs {
		input := android.PathForSourceRelaxed(ctx, inputRoot, spec.role)
		command.FlagWithInput("--input="+spec.role+"=", input)
	}
	if allowUserdebugDogfood {
		command.Flag("--allow-userdebug-dogfood")
	}
	// Do not declare files below stageRoot as Ninja outputs: Ninja creates
	// output parent directories before running a command, which would make the
	// materializer's intentionally-absent stage root exist prematurely.  A
	// sibling stamp is the graph edge; custody consumes the stage paths only
	// after this stamp is complete.
	command.Text("&& : > ").Output(stageStamp)
	rule.Build(
		"trillionnium_receipt_stage_materialize",
		"materialize Trillionnium external receipt stage",
	)
	return true
}

func addRoleArguments(
	command *android.RuleBuilderCommand,
	inputs map[string]android.Path,
	outputs map[string]android.WritablePath,
	externalStage bool,
) {
	for _, spec := range roleSpecs {
		if externalStage {
			command.FlagWithArg("--artifact-in="+spec.role+"=", inputs[spec.role].String())
		} else {
			command.FlagWithInput("--artifact-in="+spec.role+"=", inputs[spec.role])
		}
		command.FlagWithOutput("--artifact-out="+spec.role+"=", outputs[spec.role])
	}
}

func (module *ReceiptStage) GenerateAndroidBuildActions(ctx android.ModuleContext) {
	tool := receiptStageVerifier(ctx)
	if ctx.Failed() {
		return
	}
	allowUserdebugDogfood := ctx.Config().Getenv("TRILLINNIUM_ALLOW_USERDEBUG_DOGFOOD") == "true"
	var materializer android.Path
	if ctx.Config().Getenv(materializerInputRootEnv) != "" {
		materializer = receiptStageMaterializer(ctx)
		if ctx.Failed() {
			return
		}
	}

	contract := android.PathForModuleSrc(ctx, contractPath)
	baseManifest := android.PathForModuleSrc(ctx, "linux/manifest.txt")
	externalReceipt := android.PathForArbitraryOutput(ctx, stageRoot, stageReceipt)
	materializerStamp := android.PathForArbitraryOutput(ctx, stageRoot+".materialized")
	externalInputs := make(map[string]android.Path, len(roleSpecs))
	for _, spec := range roleSpecs {
		path := android.PathForArbitraryOutput(
			ctx,
			stageRoot,
			spec.stagePath,
		)
		externalInputs[spec.role] = path
	}
	materializerEnabled := false
	if materializer != nil {
		materializerEnabled = addReceiptStageMaterializer(
			ctx,
			materializer,
			contract,
			baseManifest,
			materializerStamp,
			allowUserdebugDogfood,
		)
	}

	custodyReceipt := android.PathForModuleOut(ctx, "custody", stageReceipt)
	custodyAttestation := android.PathForModuleOut(ctx, "custody", "custody.v1.json")
	custodyOutputs := make(map[string]android.WritablePath, len(roleSpecs))
	for _, spec := range roleSpecs {
		custodyOutputs[spec.role] = android.PathForModuleOut(
			ctx,
			"custody",
			spec.outputFilename,
		)
	}

	// This first rule intentionally runs before sbox.  Sbox copies inputs and
	// would erase the original OUT_DIR hard-link count.  The verifier retains
	// every original file and directory descriptor through its final copy gate.
	custodyRule := android.NewRuleBuilder(pctx, ctx)
	custodyCommand := custodyRule.Command().
		Tool(tool).
		FlagWithArg("--phase=", "custody").
		FlagWithInput("--contract=", contract).
		FlagWithOutput("--receipt-output=", custodyReceipt).
		FlagWithOutput("--custody-output=", custodyAttestation)
	if materializerEnabled {
		custodyCommand.FlagWithArg("--receipt=", externalReceipt.String())
		custodyCommand.OrderOnly(materializerStamp)
	} else {
		custodyCommand.FlagWithInput("--receipt=", externalReceipt)
	}
	if allowUserdebugDogfood {
		custodyCommand.Flag("--allow-userdebug-dogfood")
	}
	addRoleArguments(custodyCommand, externalInputs, custodyOutputs, materializerEnabled)
	custodyRule.Build(
		"trillionnium_receipt_stage_custody",
		"custody Trillionnium external receipt stage",
	)

	genDir := android.PathForModuleGen(ctx)
	sboxManifest := android.PathForModuleOut(ctx, "receipt-stage.sbox.textproto")
	publishedReceipt := android.PathForModuleGen(ctx, stageReceipt)
	publishedAttestation := android.PathForModuleGen(ctx, "custody.v1.json")
	publishedOutputs := make(map[string]android.WritablePath, len(roleSpecs))
	for _, spec := range roleSpecs {
		publishedOutputs[spec.role] = android.PathForModuleGen(ctx, spec.outputFilename)
	}

	// The publication rule sees only the complete custody set declared here.
	// SandboxInputs also copies the verifier tool, preventing undeclared reads
	// from the source tree or arbitrary OUT_DIR paths.
	publishRule := android.NewRuleBuilder(pctx, ctx).
		Sbox(genDir, sboxManifest).
		SandboxInputs()
	publishCommand := publishRule.Command().
		Tool(tool).
		FlagWithArg("--phase=", "publish").
		FlagWithInput("--contract=", contract).
		FlagWithInput("--receipt=", custodyReceipt).
		FlagWithInput("--custody-input=", custodyAttestation).
		FlagWithOutput("--receipt-output=", publishedReceipt).
		FlagWithOutput("--custody-output=", publishedAttestation)
	if allowUserdebugDogfood {
		publishCommand.Flag("--allow-userdebug-dogfood")
	}
	custodyInputs := make(map[string]android.Path, len(roleSpecs))
	for role, path := range custodyOutputs {
		custodyInputs[role] = path
	}
	addRoleArguments(publishCommand, custodyInputs, publishedOutputs, false)
	publishRule.Build(
		"trillionnium_receipt_stage_publish",
		"verify and publish Trillionnium receipt stage",
	)

	allOutputs := android.Paths{publishedReceipt, publishedAttestation}
	ctx.SetOutputFiles(android.Paths{publishedReceipt}, stageReceiptTag)
	ctx.SetOutputFiles(android.Paths{publishedAttestation}, custodyTag)
	for _, spec := range roleSpecs {
		path := publishedOutputs[spec.role]
		allOutputs = append(allOutputs, path)
		ctx.SetOutputFiles(android.Paths{path}, spec.tag)
	}
	ctx.SetOutputFiles(allOutputs, "")
}

func ReceiptStageFactory() android.Module {
	module := &ReceiptStage{}
	android.InitAndroidModule(module)
	return module
}
