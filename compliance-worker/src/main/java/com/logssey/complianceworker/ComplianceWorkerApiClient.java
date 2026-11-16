package com.logssey.complianceworker;

import static com.logssey.complianceworker.WorkerDtos.ClaimedJob;
import static com.logssey.complianceworker.WorkerDtos.LeaseResponse;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;

import tools.jackson.databind.json.JsonMapper;

@Component
public class ComplianceWorkerApiClient {

    private static final String TOKEN_HEADER = "X-Compliance-Worker-Token";

    private final ComplianceWorkerProperties properties;
    private final HttpClient http;
    private final JsonMapper json;

    @Autowired
    public ComplianceWorkerApiClient(ComplianceWorkerProperties properties) {
        this(properties, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build(),
                JsonMapper.builder().build());
    }

    ComplianceWorkerApiClient(ComplianceWorkerProperties properties, HttpClient http, JsonMapper json) {
        this.properties = properties;
        this.http = http;
        this.json = json;
    }

    Optional<ClaimedJob> claim() throws IOException, InterruptedException {
        byte[] body = json.writeValueAsBytes(java.util.Map.of("workerId", properties.workerId()));
        var response = send(jsonRequest("/internal/v1/compliance/jobs/claim", body));
        if (response.statusCode() == 204) return Optional.empty();
        requireStatus(response, 200);
        return Optional.of(json.readValue(response.body(), ClaimedJob.class));
    }

    boolean heartbeat(ClaimedJob job) throws IOException, InterruptedException {
        byte[] body = json.writeValueAsBytes(java.util.Map.of(
                "leaseToken", job.leaseToken(), "leaseGeneration", job.leaseGeneration()));
        var response = send(jsonRequest("/internal/v1/compliance/jobs/" + job.jobId() + "/heartbeat", body));
        if (response.statusCode() == 409) return false;
        requireStatus(response, 200);
        json.readValue(response.body(), LeaseResponse.class);
        return true;
    }

    void submit(ClaimedJob job, Path result) throws IOException, InterruptedException {
        String boundary = "logssey-" + java.util.UUID.randomUUID();
        byte[] prefix = ("--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"result.ocsf.json\"\r\n"
                + "Content-Type: application/json\r\n\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] suffix = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);
        String query = "?leaseToken=" + encode(job.leaseToken().toString())
                + "&leaseGeneration=" + job.leaseGeneration();
        var request = baseRequest("/internal/v1/compliance/jobs/" + job.jobId() + "/result" + query)
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArrays(List.of(prefix, Files.readAllBytes(result), suffix)))
                .build();
        requireStatus(send(request), 200);
    }

    void fail(ClaimedJob job, String errorCode, boolean retryable) throws IOException, InterruptedException {
        byte[] body = json.writeValueAsBytes(java.util.Map.of(
                "leaseToken", job.leaseToken(), "leaseGeneration", job.leaseGeneration(),
                "errorCode", errorCode, "retryable", retryable));
        var response = send(jsonRequest("/internal/v1/compliance/jobs/" + job.jobId() + "/failure", body));
        if (response.statusCode() != 204 && response.statusCode() != 409) requireStatus(response, 204);
    }

    private HttpRequest jsonRequest(String path, byte[] body) {
        return baseRequest(path).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
    }

    private HttpRequest.Builder baseRequest(String path) {
        URI uri = properties.apiBaseUrl().resolve(path);
        return HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30))
                .header(TOKEN_HEADER, properties.token());
    }

    private HttpResponse<byte[]> send(HttpRequest request) throws IOException, InterruptedException {
        return http.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }

    private static void requireStatus(HttpResponse<?> response, int expected) throws IOException {
        if (response.statusCode() != expected) {
            throw new IOException("Compliance API returned HTTP " + response.statusCode());
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
