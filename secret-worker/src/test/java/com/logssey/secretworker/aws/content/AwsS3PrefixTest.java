package com.logssey.secretworker.aws.content;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class AwsS3PrefixTest {
    static AwsContentScope prefix() {
        return AwsContentScope.fromApprovedRef("AWS_S3_OBJECT_CONTENT",
                "aws://123456789012/ap-northeast-1/s3/prefix/demo-bucket/demo%2F", "CURRENT_VALUE_ONLY");
    }

    @Test void pagesIncludeNestedAndNewFilesWithoutReadingSiblingPrefixes() {
        var read = new ArrayList<String>();
        var buffers = new ArrayList<byte[]>();
        AwsContentReader reader = new AwsContentReader() {
            public ObjectPage list(AwsContentScope p, String token) {
                assertEquals("demo/", p.objectKey());
                return token == null ? new ObjectPage(List.of("demo/", "demo/a.env"), "page2")
                        : new ObjectPage(List.of("demo/sub/new.env", "demo-other/private.env"), null);
            }
            public byte[] read(AwsContentScope p, int max) {
                read.add(p.objectKey()); byte[] b = "test".getBytes(StandardCharsets.UTF_8); buffers.add(b); return b;
            }
        };
        var result = new AwsContentCollector(reader).collect(prefix(), true, 100, (s,b) ->
                assertTrue(s.objectKey().startsWith("demo/")));
        assertEquals(List.of("demo/a.env", "demo/sub/new.env"), read);
        assertEquals(2, result.objectCount());
        assertEquals(AwsContentCollector.Status.PARTIAL, result.status());
        assertEquals(List.of(AwsContentCollector.GapCode.INVALID_OBJECT_KEY), result.gaps());
        buffers.forEach(b -> assertArrayEquals(new byte[b.length], b));
    }

    @Test void partialReadAndPaginationLoopAreNotReportedAsComplete() {
        AwsContentReader reader = new AwsContentReader() {
            public ObjectPage list(AwsContentScope p, String token) {
                return new ObjectPage(List.of("demo/a.env", "demo/denied.env"), "same");
            }
            public byte[] read(AwsContentScope p, int max) {
                if(p.objectKey().contains("denied")) throw new ReadFailure(FailureCode.ACCESS_DENIED);
                return new byte[]{65};
            }
        };
        var result = new AwsContentCollector(reader).collect(prefix(), true, 100, (s,b)->{});
        assertEquals(1, result.objectCount());
        assertEquals(AwsContentCollector.Status.PARTIAL, result.status());
        assertTrue(result.gaps().contains(AwsContentCollector.GapCode.ACCESS_DENIED));
        assertTrue(result.gaps().contains(AwsContentCollector.GapCode.PAGINATION_LOOP));
    }

    @Test void revalidationIsBoundToOneChildAndRejectsEscapeOrAnotherScope() {
        var p=prefix();
        String ref=p.childSourceRef(14,"demo/sub/a b.env");
        assertEquals("demo/sub/a b.env",p.resolveSource(14,ref).objectKey());
        assertThrows(IllegalArgumentException.class,()->p.resolveSource(15,ref));
        assertThrows(IllegalArgumentException.class,()->p.resolveSource(14,"aws-content-scope:14:demo-other%2Fa.env"));
        assertThrows(IllegalArgumentException.class,()->p.child("demo2/a.env"));
        assertThrows(IllegalArgumentException.class,()->AwsContentScope.fromApprovedRef("AWS_S3_OBJECT_CONTENT",
                "aws://123456789012/ap-northeast-1/s3/prefix/demo-bucket/demo", "CURRENT_VALUE_ONLY"));
    }

    @Test void emptyPrefixIsSuccessfulButDeniedListingIsNot() {
        AwsContentReader empty=new AwsContentReader() {
            public ObjectPage list(AwsContentScope p,String token){return new ObjectPage(List.of(),null);}
            public byte[] read(AwsContentScope p,int max){throw new AssertionError();}
        };
        assertEquals(AwsContentCollector.Status.SUCCEEDED,
                new AwsContentCollector(empty).collect(prefix(),true,100,(s,b)->{}).status());
        AwsContentReader denied=new AwsContentReader() {
            public ObjectPage list(AwsContentScope p,String token){throw new ReadFailure(FailureCode.ACCESS_DENIED);}
            public byte[] read(AwsContentScope p,int max){throw new AssertionError();}
        };
        assertEquals(AwsContentCollector.Status.FAILED,
                new AwsContentCollector(denied).collect(prefix(),true,100,(s,b)->{}).status());
    }
}
