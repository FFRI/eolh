/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package logger

import (
	"runtime"
	"strings"
)

type callerInfo struct {
	pkg       string
	file      string
	line      int
	functions []string
}

// getCallerInfo returns package, file and line from a function
// based on the given number of skips (stack frames).
func getCallerInfo(skip int) *callerInfo {
	var (
		pkg       string
		file      string
		line      int
		functions []string
	)

	// maximum depth of 20
	pcs := make([]uintptr, 20)
	n := runtime.Callers(skip+2, pcs)
	pcs = pcs[:n-1]

	frames := runtime.CallersFrames(pcs)
	firstCaller := true
	for {
		frame, more := frames.Next()
		if !more {
			break
		}

		fn := frame.Function
		fnStart := strings.LastIndexByte(fn, '/')
		if fnStart == -1 {
			fnStart = 0
		} else {
			fnStart++
		}

		fn = fn[fnStart:]
		pkgEnd := strings.IndexByte(fn, '.')
		if pkgEnd == -1 {
			fnStart = 0
		} else {
			fnStart = pkgEnd + 1
		}
		functions = append(functions, fn[fnStart:])

		if firstCaller {
			line = frame.Line
			file = frame.File
			// set file as relative path
			pat := "eolh/"
			eolhIndex := strings.Index(file, pat)
			if eolhIndex != -1 {
				file = file[eolhIndex+len(pat):]
			}
			pkg = fn[:pkgEnd]

			firstCaller = false
		}
	}

	return &callerInfo{
		pkg:       pkg,
		file:      file,
		line:      line,
		functions: functions,
	}
}
