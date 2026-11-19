-- IaC 보안: PR 제목 (대시보드 PR 목록·상세에 표시). infrastructure 의 iac-report 가 실행을 등록할 때 GitHub 에서 받아 보낸다.
-- PR 작성자가 쓴 글이라 화면은 텍스트로만 표시한다. main 점검(PUSH) 실행은 비어 있다.
ALTER TABLE iac_runs ADD COLUMN pr_title VARCHAR(256);
