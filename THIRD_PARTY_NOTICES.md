# Third-Party Notices

RISU Verify v0.4.0-rc1 vendors the frozen `Consequence-Preserving Projections v0.7.0` release archive without modification. The authoritative notices for material inside that scientific archive remain inside the vendored archive.

The audit-hardened wrapper also retains selected, pinned excerpts or normalized public-evidence snapshots from independently developed upstream projects for reproducibility and research analysis. These materials remain subject to their upstream licenses and notices.

| Retained material | Upstream | Role in RISU Verify | Revision / identity |
|---|---|---|---|
| GitHub MCP source blocks | `github/github-mcp-server` | External projection / historical source evidence | pinned Git commits and recorded blob IDs in each provenance manifest |
| `go-github` merge-guard block | `google/go-github` | Source-operation capability evidence for Case 001 | pinned source revision recorded in Case 001 provenance |
| Azure DevOps MCP wiki source excerpt | `microsoft/azure-devops-mcp` | External projection evidence for Case 002 | commit `7675bb70e3ab2cd84e2991f453a8fdc9d0c8ce89`, recorded blob `36932f79ab5acee34f72bb8bf6740329601e31bc` |
| Public GitHub issue/PR metadata | `github/github-mcp-server` | Historical context and empirical corroboration for Case 003 | issue #2133 / PR #2134 |

RISU does not claim ownership of those upstream materials. The wrapper's provenance records distinguish selected local evidence bytes, connector-normalized public snapshots, semantic interpretation snapshots, and the frozen core's model-relative assurance artifacts.
