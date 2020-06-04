/*
Software Name : Remote Key Server
Version: 0.9.0
SPDX-FileCopyrightText: Copyright (c) 2020 Orange
SPDX-License-Identifier: MPL-2.0

This software is distributed under the Mozilla Public License 2.0,
the text of which is available at https://www.mozilla.org/en-US/MPL/2.0/
or see the "LICENSE" file for more details.

Author: Glenn Feunteun, Celine Nicolas
*/
package main

// code based on technique explained here:
// https://www.elastic.co/blog/code-coverage-for-your-golang-system-tests
// you can look there if you want to see how not to execute this test
// when running unit test etc.

// This file is mandatory as otherwise the instrumented rks binary is not generated correctly.

import (
	"testing"
)

// Test started when the test binary is started. Only calls main.
func TestSystem(t *testing.T) {
	main()
}
