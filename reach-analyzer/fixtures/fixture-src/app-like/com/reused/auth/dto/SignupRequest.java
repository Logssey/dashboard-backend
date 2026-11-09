package com.reused.auth.dto;

import java.util.List;

public record SignupRequest(String email, String password, String nickname, List<String> interests) {
}
