# Unit 002-R authoring note 001

The selected target is not a post-control hunt. `corpus01-unit-002` was enrollment position 2 in the original verdict-blind Corpus 0.1 enrollment, before any Corpus primary outcome. Unit 002-R inherits that order exactly.

Before inspecting Unit-specific target semantics in detail, `SELECTION_FREEZE.json` was committed. SOURCE semantics were then reconstructed and frozen before TARGET lane authoring. Static TARGET evidence is split across dependency identity, callable surface, request serialization, and result interpretation so that an evidence failure cannot be hidden inside a monolithic target assertion.

A target-only black-box qualification is intentionally placed before TARGET freeze. It builds the exact selected Octokit revision under its lockfile, injects mock 200 and 409 provider responses, and observes only carrier behavior. It does not contact GitHub's live service, execute RISU, or determine the scientific verdict.
