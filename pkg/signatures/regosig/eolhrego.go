/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package regosig

import (
	"bytes"
	"context"
	"encoding/json"
	"eolh/pkg/detect"
	"eolh/pkg/protocol"
	"eolh/pkg/trace"
	"fmt"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

type RegoSignature struct {
	cb             detect.SignatureHandler
	compiledRego   *ast.Compiler
	matchPQ        rego.PreparedEvalQuery
	metadata       detect.SignatureMetadata
	selectedEvents []detect.SignatureEventSelector
}

const queryMatch string = "data.%s.eolh_match"
const querySelectedEvents string = "data.%s.eolh_selected_events"
const queryMetadata string = "data.%s.__rego_metadoc__"
const packageNameRegex string = `package\s.*`

func NewRegoSignature(target string, regoCodes ...string) (detect.Signature, error) {
	var err error
	res := RegoSignature{}
	regoMap := make(map[string]string)
	re := regexp.MustCompile(packageNameRegex)

	var pkgName string
	for _, regoCode := range regoCodes {
		var regoModuleName string
		splittedName := strings.Split(re.FindString(regoCode), " ")
		if len(splittedName) <= 1 {
			return nil, fmt.Errorf("invalid rego code received")
		}
		regoModuleName = splittedName[1]
		pkgName = regoModuleName
		regoMap[regoModuleName] = regoCode
	}
	res.compiledRego, err = ast.CompileModules(regoMap)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	res.matchPQ, err = rego.New(
		rego.Target(target),
		rego.Compiler(res.compiledRego),
		rego.Query(fmt.Sprintf(queryMatch, pkgName)),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	res.metadata, err = res.getMetadata(pkgName)
	if err != nil {
		return nil, err
	}
	res.selectedEvents, err = res.getSelectedEvents(pkgName)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (sig *RegoSignature) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *RegoSignature) GetMetadata() (detect.SignatureMetadata, error) {
	return sig.metadata, nil
}

func (sig *RegoSignature) getMetadata(pkgName string) (detect.SignatureMetadata, error) {
	evalRes, err := sig.evalQuery(fmt.Sprintf(queryMetadata, pkgName))
	if err != nil {
		return detect.SignatureMetadata{}, err
	}
	resJSON, err := json.Marshal(evalRes)
	if err != nil {
		return detect.SignatureMetadata{}, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res detect.SignatureMetadata
	err = dec.Decode(&res)
	if err != nil {
		return detect.SignatureMetadata{}, err
	}
	return res, nil
}

func (sig *RegoSignature) OnSignal(signal detect.Signal) error {
	return fmt.Errorf("function OnSignal is not implemented")
}

func (sig *RegoSignature) Close() {}

func (sig *RegoSignature) evalQuery(query string) (interface{}, error) {
	pq, err := rego.New(
		rego.Compiler(sig.compiledRego),
		rego.Query(query),
	).PrepareForEval(context.TODO())
	if err != nil {
		return nil, err
	}
	evalRes, err := pq.Eval(context.TODO())
	if err != nil {
		return nil, err
	}
	if len(evalRes) > 0 && len(evalRes[0].Expressions) > 0 && evalRes[0].Expressions[0].Value != nil {
		return evalRes[0].Expressions[0].Value, nil
	}
	return nil, nil
}

// this is a *set* rule that defines the rule's SelectedEvents
func (sig *RegoSignature) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return sig.selectedEvents, nil
}

func (sig *RegoSignature) getSelectedEvents(pkgName string) ([]detect.SignatureEventSelector, error) {
	evalRes, err := sig.evalQuery(fmt.Sprintf(querySelectedEvents, pkgName))
	if err != nil {
		return nil, err
	}
	resJSON, err := json.Marshal(evalRes)
	if err != nil {
		return nil, err
	}
	var res []detect.SignatureEventSelector
	err = json.Unmarshal(resJSON, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (sig *RegoSignature) OnEvent(event protocol.Event) error {
	input := rego.EvalInput(event.Payload.(trace.Event))
	results, err := sig.matchPQ.Eval(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("evaluating rego: %w", err)
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 && results[0].Expressions[0].Value != nil {
		switch v := results[0].Expressions[0].Value.(type) {
		case bool:
			if v {
				sig.cb(detect.Finding{
					Data:        nil,
					Event:       event,
					SigMetadata: sig.metadata,
				})
			}
		case map[string]interface{}:
			sig.cb(detect.Finding{
				Data:        v,
				Event:       event,
				SigMetadata: sig.metadata,
			})
		}
	}
	return nil
}
