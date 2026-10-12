package com.logssey.credential.scan.notion;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.logssey.credential.notion.Sleeper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/** Notion 페이지 읽기 (POST /v1/search, GET /v1/pages/{id}/markdown). WireMock이 Notion인 척한다 */
class NotionPageReaderTest {

    private static final String TOKEN = "test-collector-token";

    @RegisterExtension
    static WireMockExtension notion = WireMockExtension.newInstance().options(wireMockConfig().dynamicPort()).build();

    private final List<Duration> waits = new ArrayList<>();
    private NotionPageReader reader;

    @BeforeEach
    void setUp() {
        waits.clear();
        Sleeper recording = waits::add;
        reader = new NotionPageReader(notion.baseUrl(), TOKEN, recording);
    }

    @Test
    @DisplayName("페이지 목록: 페이지만 걸러 요청하고, next_cursor로 끝까지 받고, 제목을 읽는다")
    void listsSharedPagesWithPagination() {
        notion.stubFor(post(urlPathEqualTo("/v1/search"))
                .withRequestBody(matchingJsonPath("$.start_cursor", com.github.tomakehurst.wiremock.client.WireMock.absent()))
                .willReturn(okJson("""
                        { "object": "list", "results": [
                            { "object": "page", "id": "page-1", "properties": {
                                "title": { "type": "title", "title": [ { "plain_text": "Logssey " }, { "plain_text": "탐지 테스트" } ] } } }
                          ], "has_more": true, "next_cursor": "cursor-2" }
                        """)));
        notion.stubFor(post(urlPathEqualTo("/v1/search"))
                .withRequestBody(matchingJsonPath("$.start_cursor", equalTo("cursor-2")))
                .willReturn(okJson("""
                        { "object": "list", "results": [
                            { "object": "page", "id": "page-2", "properties": {} }
                          ], "has_more": false, "next_cursor": null }
                        """)));

        List<NotionPage> pages = reader.listSharedPages();

        assertThat(pages).containsExactly(new NotionPage("page-1", "Logssey 탐지 테스트"), new NotionPage("page-2", "제목 없음"));
        notion.verify(2, postRequestedFor(urlPathEqualTo("/v1/search"))
                .withHeader("Authorization", equalTo("Bearer " + TOKEN))
                .withHeader("Notion-Version", equalTo("2026-03-11"))
                .withRequestBody(equalToJson("{ \"filter\": { \"property\": \"object\", \"value\": \"page\" } }", true, true)));
    }

    @Test
    @DisplayName("페이지 내용: Markdown 글을 받는다")
    void readsMarkdown() {
        notion.stubFor(get(urlPathEqualTo("/v1/pages/page-1/markdown")).willReturn(okJson("""
                { "object": "page_markdown", "id": "page-1", "markdown": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
                  "truncated": false, "unknown_block_ids": [] }
                """)));

        assertThat(reader.readMarkdown("page-1")).isEqualTo("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        notion.verify(getRequestedFor(urlPathEqualTo("/v1/pages/page-1/markdown"))
                .withHeader("Notion-Version", equalTo("2026-03-11")));
    }

    @Test
    @DisplayName("429: retry-after만큼 기다렸다가 다시 요청해 성공")
    void retriesOnRateLimit() {
        notion.stubFor(get(urlPathEqualTo("/v1/pages/page-1/markdown")).inScenario("rate")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "2"))
                .willSetStateTo("ok"));
        notion.stubFor(get(urlPathEqualTo("/v1/pages/page-1/markdown")).inScenario("rate")
                .whenScenarioStateIs("ok")
                .willReturn(okJson("{ \"object\": \"page_markdown\", \"id\": \"page-1\", \"markdown\": \"hello\", \"truncated\": false, \"unknown_block_ids\": [] }")));

        assertThat(reader.readMarkdown("page-1")).isEqualTo("hello");
        assertThat(waits).containsExactly(Duration.ofSeconds(2));
    }

    @Test
    @DisplayName("401·404는 상태 코드와 code를 담아 실패한다")
    void failsWithStatusAndCode() {
        notion.stubFor(post(urlPathEqualTo("/v1/search")).willReturn(aResponse().withStatus(401)
                .withHeader("Content-Type", "application/json")
                .withBody("{ \"object\": \"error\", \"status\": 401, \"code\": \"unauthorized\", \"message\": \"x\" }")));
        notion.stubFor(get(urlPathEqualTo("/v1/pages/gone/markdown")).willReturn(aResponse().withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("{ \"object\": \"error\", \"status\": 404, \"code\": \"object_not_found\", \"message\": \"x\" }")));

        assertThatThrownBy(() -> reader.listSharedPages())
                .isInstanceOfSatisfying(NotionReadException.class, e -> {
                    assertThat(e.httpStatus()).isEqualTo(401);
                    assertThat(e.code()).isEqualTo("unauthorized");
                });
        assertThatThrownBy(() -> reader.readMarkdown("gone"))
                .isInstanceOfSatisfying(NotionReadException.class, e -> assertThat(e.httpStatus()).isEqualTo(404));
    }

    @Test
    @DisplayName("toString에 토큰이 나오지 않는다")
    void toStringMasksToken() {
        assertThat(reader.toString()).doesNotContain(TOKEN);
    }
}
