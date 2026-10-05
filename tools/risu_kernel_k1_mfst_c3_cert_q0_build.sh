#!/usr/bin/env bash
set -euo pipefail
mkdir -p build
python3 -m py_compile   kernel/k1_checker_w10_refinement_cert.py   tools/risu_kernel_k1_mfst_c3_cert_q0_common.py
cd kernel
test -z "$(gofmt -d k1_w8_json.go k1_w8_model.go k1_w8_exec.go k1_checker_w8.go)"
GO111MODULE=off CGO_ENABLED=0 go vet k1_w8_json.go k1_w8_model.go k1_w8_exec.go k1_checker_w8.go
CGO_ENABLED=0 go build -o ../build/k1_checker_w8 k1_w8_json.go k1_w8_model.go k1_w8_exec.go k1_checker_w8.go
cd ..
test -z "$(gofmt -d kernel/k1_checker_w6.go)"
GO111MODULE=off CGO_ENABLED=0 go vet kernel/k1_checker_w6.go
CGO_ENABLED=0 go build -o build/k1_checker_w6 kernel/k1_checker_w6.go
test -z "$(gofmt -d kernel/k1_checker_w11_refinement_cert.go)"
GO111MODULE=off CGO_ENABLED=0 go vet kernel/k1_checker_w11_refinement_cert.go
CGO_ENABLED=0 go build -o build/k1_checker_w11_refinement_cert kernel/k1_checker_w11_refinement_cert.go
if [[ "${1:-}" == "cross" ]]; then
  cd kernel
  test -z "$(gofmt -d k1_w8_cross_replay_driver.go)"
  GO111MODULE=off CGO_ENABLED=0 go vet k1_w8_json.go k1_w8_model.go k1_w8_exec.go k1_w8_cross_replay_driver.go
  CGO_ENABLED=0 go build -o ../build/k1_w8_cross_replay k1_w8_json.go k1_w8_model.go k1_w8_exec.go k1_w8_cross_replay_driver.go
fi
echo Q0_BUILD_PASS
