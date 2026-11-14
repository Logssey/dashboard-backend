-- Reach 앱 코드를 Re:Used의 세 앱(API·WEB·CHAT) 고정에서 설치마다 정하는 설정(logssey.reach.apps)으로 바꾼다 (PRD FR-15)
-- DB는 형식만 본다. 어떤 코드가 있는지는 설정이 정하고, 서버가 요청을 받을 때 대조한다
-- V34의 열 CHECK는 이름을 주지 않아 PostgreSQL 기본 이름(reach_targets_app_check)이다
ALTER TABLE reach_targets DROP CONSTRAINT reach_targets_app_check;
ALTER TABLE reach_targets ADD CONSTRAINT ck_reach_targets_app CHECK (app ~ '^[A-Z][A-Z0-9_]{0,9}$');
