package jakarta.servlet;

public class HttpMethodConstraintElement {
    private final String method;

    public HttpMethodConstraintElement(String method) {
        this.method = method;
    }

    public String getMethodName() {
        return method;
    }
}
