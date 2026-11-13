# B25 소유자 직접 GitHub 승인 설정

현재 B25 요청은 실제 사용자의 승인 전 상태입니다. 승인 없이 저장소 쓰기를 실행하지 않습니다.

1. [risu-verify의 Environments 설정](https://github.com/risu-research/risu-verify/settings/environments)에서 새 환경을 생성하고 이름을 정확히 risu-b25-human-owner-approval로 설정합니다.
2. Required reviewers를 활성화하고 GitHub 계정 moon10021017을 지정합니다.
3. 같은 계정으로 실행을 트리거하고 승인할 때는 Prevent self-review를 해제합니다. 더 강한 별도 승인자 시험은 두 번째 사람을 reviewer로 지정하고 이 기능을 켜서 수행합니다.
4. Allow administrators to bypass configured protection rules 해제 권장, Deployment branches는 qualification/p6b25-real-review-credential-isolation-20261112만 허용합니다.
5. 설정이 끝나면 채팅에 '설정했어'라고 알려주세요. 그때 연구 브랜치에 REQUEST_HUMAN_REVIEW.txt 마커를 생성해서 Workflow 실행을 시작합니다.
6. 소유자가 GitHub Actions 실행 화면의 Review deployments에서 Approve and deploy를 직접 누릅니다. 해당 승인 기록이 없으면 B25 작성기는 한 줄도 변경하지 않습니다.

승인 대상은 연구 브랜치의 benchmarks/p6b25/owner_only_resource.txt 파일 하나이고, 변경 전후 내용과 Git 해시가 소스에 고정되어 있습니다. GITHUB_TOKEN은 GitHub Actions가 각 작업에 발급하므로 개인 액세스 토큰, GitHub App 키 또는 비밀번호를 보내거나 생성할 필요가 없습니다.

현재 인간 승인은 수행되지 않았습니다. 읽기 전용 job으로 실제 GitHub PUT HTTP 403과 대상 파일 미생성, 기존 코드를 포함한 3개 OS 테스트 539건은 확인했습니다.

이번 테스트에서는 이 계정의 직접 승인을 검증할 수 있으나, 서로 다른 두 사람의 검토는 아직 아닙니다. 사람의 승인 출처는 GitHub Actions의 해당 실행에 대한 review history API로 재검증합니다.
