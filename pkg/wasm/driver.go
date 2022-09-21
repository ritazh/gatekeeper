package wasm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	constraints2 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	target2 "github.com/open-policy-agent/gatekeeper/pkg/target"
	"github.com/open-policy-agent/opa/storage"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func NewDriver() *Driver {
	return &Driver{
		wasmModules: make(map[string]string),
	}
}

type Driver struct {
	wasmModules map[string]string
}

type WasmDecision struct {
	Decision   []byte
	Name       string
	Constraint *unstructured.Unstructured
}

var _ drivers.Driver = &Driver{}

func (d *Driver) AddTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
	if len(ct.Spec.Targets) == 0 {
		return nil
	}
	/// TODO: another option is to pull from OCI registry
	wasmCodeBase64 := ct.Spec.Targets[0].Rego // Wasm

	if wasmCodeBase64 == "" {
		return fmt.Errorf("wasm code is empty for template: %q", ct.Name)
	}
	/// TODO: mutax
	wasmCode, err := base64.StdEncoding.DecodeString(wasmCodeBase64)
	if err != nil {
		return err
	}
	d.wasmModules[ct.Name] = string(wasmCode)
	return nil
}

func (d *Driver) RemoveTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
	delete(d.wasmModules, ct.Name)

	return nil
}

func (d *Driver) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	wasmModuleName := strings.ToLower(constraint.GetKind())

	_, found := d.wasmModules[wasmModuleName]
	if !found {
		return fmt.Errorf("no wasmModuleName with name: %q", wasmModuleName)
	}

	return nil
}

func (d *Driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	return nil
}

func (d *Driver) AddData(ctx context.Context, target string, path storage.Path, data interface{}) error {
	return nil
}

func (d *Driver) RemoveData(ctx context.Context, target string, path storage.Path) error {
	return nil
}

func (d *Driver) Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...drivers.QueryOpt) ([]*types.Result, *string, error) {
	stdout := bytes.NewBuffer(nil)

	// WebAssembly 2.0 allows use of any version of TinyGo, including 0.24+.
	// If we don't specify WithWasmCore2, we need WithFeatureBulkMemoryOperations(true).WithFeatureSignExtensionOps(true).WithFeatureNonTrappingFloatToIntConversion(true)
	c := wazero.NewRuntimeConfig().WithWasmCore2()
	///TODO: is there a better way to handle this so we dont have to create it for every query
	r := wazero.NewRuntimeWithConfig(ctx, c)
	defer r.Close(ctx)
	// By default, I/O streams are discarded and there's no file system.
	config := wazero.NewModuleConfig().WithStdout(stdout).WithStderr(os.Stderr)

	_, err := r.NewModuleBuilder("env").
		ExportFunction("log", logString).
		Instantiate(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	// TinyGo needs wasi to
	// implement functions such as panic.
	// Need to see if we absolutely need it later
	if _, err = wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		return nil, nil, err
	}

	gkr := review.(*target2.GkReview)

	obj := &unstructured.Unstructured{
		Object: make(map[string]interface{}),
	}

	err = obj.UnmarshalJSON(gkr.Object.Raw)
	if err != nil {
		return nil, nil, err
	}

	var allDecisions []*WasmDecision
	for _, constraint := range constraints {
		wasmModuleName := strings.ToLower(constraint.GetKind())
		wasmModule, found := d.wasmModules[wasmModuleName]
		if !found {
			continue
		}

		paramsStruct, _, err := unstructured.NestedFieldNoCopy(constraint.Object, "spec", "parameters")
		if err != nil {
			return nil, nil, err
		}

		params, err := json.Marshal(paramsStruct)
		if err != nil {
			return nil, nil, err
		}

		fmt.Println("Running wasm module: ", wasmModuleName)
		moduleBytes := []byte(wasmModule)
		code, err := r.CompileModule(ctx, moduleBytes, wazero.NewCompileConfig())
		if err != nil {
			return nil, nil, err
		}
		// pass in object as os.Args[1] and params as os.Args[2]
		mod, err := r.InstantiateModule(ctx, code, config.WithArgs("gatekeeper", string(gkr.Object.Raw), string(params)))
		if err != nil {
			return nil, nil, err
		}
		modEval := mod.ExportedFunction("eval")

		_, err = modEval.Call(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("error running wasm module %s: %v", wasmModuleName, err)
		}
		decision := stdout.Bytes()
		decisionBool, err := strconv.ParseBool(string(decision))
		if err != nil {
			return nil, nil, err
		}
		if !decisionBool {
			wasmDecision := &WasmDecision{
				Decision:   decision,
				Name:       constraint.GetName(),
				Constraint: constraint,
			}

			allDecisions = append(allDecisions, wasmDecision)
		}
	}
	if len(allDecisions) == 0 {
		return nil, nil, nil
	}

	results := make([]*types.Result, len(allDecisions))
	for i, wasmDecision := range allDecisions {
		enforcementAction, found, err := unstructured.NestedString(wasmDecision.Constraint.Object, "spec", "enforcementAction")
		if err != nil {
			return nil, nil, err
		}
		if !found {
			enforcementAction = constraints2.EnforcementActionDeny
		}

		results[i] = &types.Result{
			Metadata: map[string]interface{}{
				"name": wasmDecision.Name,
			},
			Constraint:        wasmDecision.Constraint,
			Msg:               string(wasmDecision.Decision),
			EnforcementAction: enforcementAction,
		}
	}

	return results, nil, nil
}

func logString(ctx context.Context, m api.Module, offset, byteCount uint32) {
	buf, ok := m.Memory().Read(ctx, offset, byteCount)
	if !ok {
		panic("Memory.Read out of range")
	}
	fmt.Println(string(buf))
}

func (d *Driver) Dump(ctx context.Context) (string, error) {
	//TODO implement me
	panic("implement me")
}
