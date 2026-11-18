package com.logssey.credential.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 등록·삭제는 관리자만, 목록·미리보기는 로그인한 누구나 */
class CustomKeyPatternServiceTest {

    private static final CustomKeyPatternService.PatternRequest RIK = new CustomKeyPatternService.PatternRequest(
            "사내 RIK 키", "rik_", KeyCharset.HEX_LOWER, 32, true, null);

    private final CustomKeyPatternRepository repository = mock(CustomKeyPatternRepository.class);
    private final CustomKeyPatternService service = new CustomKeyPatternService(repository);

    @Test
    @DisplayName("관리자는 형식을 등록할 수 있다")
    void adminCanCreate() {
        when(repository.isAdmin("admin")).thenReturn(true);
        when(repository.insert("사내 RIK 키", "rik_", KeyCharset.HEX_LOWER, 32, true, "admin"))
                .thenReturn(new CustomKeyPatternRepository.StoredPattern(
                        1, "사내 RIK 키", "rik_", KeyCharset.HEX_LOWER, 32, true, "admin", Instant.EPOCH));

        assertThat(service.create("admin", RIK).rule()).isEqualTo("rik_[0-9a-f]{32}");
    }

    @Test
    @DisplayName("관리자가 아니면 등록·삭제가 403이고 DB를 건드리지 않는다")
    void nonAdminIsForbidden() {
        when(repository.isAdmin("viewer")).thenReturn(false);

        assertThatThrownBy(() -> service.create("viewer", RIK))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.errorCode()).isEqualTo(ErrorCode.FORBIDDEN))
                .hasMessageContaining("관리자만");
        assertThatThrownBy(() -> service.delete("viewer", 1))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
        verify(repository, never()).insert(anyString(), anyString(), any(), anyInt(), anyBoolean(), anyString());
        verify(repository, never()).delete(anyLong());
    }

    @Test
    @DisplayName("로그인 정보가 없으면 401")
    void anonymousIsUnauthenticated() {
        assertThatThrownBy(() -> service.create(null, RIK))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.errorCode()).isEqualTo(ErrorCode.UNAUTHENTICATED));
    }

    @Test
    @DisplayName("목록은 누구나 볼 수 있고, 등록 가능 여부(canManage)를 함께 준다")
    void listShowsCanManage() {
        when(repository.findAll()).thenReturn(List.of());
        when(repository.isAdmin("admin")).thenReturn(true);
        when(repository.isAdmin("viewer")).thenReturn(false);

        assertThat(service.list("admin").canManage()).isTrue();
        assertThat(service.list("viewer").canManage()).isFalse();
    }

    @Test
    @DisplayName("미리보기는 저장하지 않으므로 관리자가 아니어도 된다")
    void previewIsOpen() {
        assertThat(service.preview(RIK).rule()).isEqualTo("rik_[0-9a-f]{32}");
        verify(repository, never()).isAdmin(anyString());
    }
}
