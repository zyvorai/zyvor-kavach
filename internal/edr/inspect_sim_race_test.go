// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//go:build race

package edr

// The race detector slows byte loops roughly 10x; the 32 MiB runtime budget
// test is only meaningful without it.
const simRaceBuild = true
