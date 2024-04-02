/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package signatures

import (
	"bytes"
	"eolh/pkg/detect"
	"eolh/pkg/logger"
	"eolh/pkg/signatures/regosig"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/compile"
)

func findGoSigs() []detect.Signature {
	var sigs []detect.Signature
	sigs = append(sigs, &Drop{})
	sigs = append(sigs, &PidSpoofing{})
	sigs = append(sigs, &CryptoMiner{})
	sigs = append(sigs, &Tor{})
	// Add your signatures below
	// sig = append(sig, &YOUR_SIGNATURE{})
	return sigs
}

func Find() ([]detect.Signature, error) {
	var sigs []detect.Signature
	gosigs := findGoSigs()
	sigs = append(sigs, gosigs...)
	opasigs, err := findRegoSigs(compile.TargetRego, "signatures")
	if err != nil {
		return nil, err
	}
	sigs = append(sigs, opasigs...)
	return sigs, nil
}

func findRegoSigs(target string, dir string) ([]detect.Signature, error) {
	modules := make(map[string]string)
	var res []detect.Signature

	errWD := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Errorw("Finding rego sigs", err)
			return err
		}
		if d.IsDir() {
			return nil
		}
		regoCode, err := os.ReadFile(path)
		if err != nil {
			logger.Errorw("Readling file " + path + ": " + err.Error())
		}
		modules[path] = string(regoCode)
		sig, err := regosig.NewRegoSignature(target, string(regoCode))
		if err != nil {
			newlineOffset := bytes.Index(regoCode, []byte("\n"))
			if newlineOffset == -1 {
				codeLength := len(regoCode)
				if codeLength < 22 {
					newlineOffset = codeLength
				} else {
					newlineOffset = 22
				}
			}
			logger.Errorw("Creating rego signature with: " + string(regoCode[0:newlineOffset]) + ": " + err.Error())
			return nil
		}
		res = append(res, sig)
		return nil
	})
	if errWD != nil {
		logger.Errorw("Walking dir", "error", errWD)
	}
	return res, nil
}
