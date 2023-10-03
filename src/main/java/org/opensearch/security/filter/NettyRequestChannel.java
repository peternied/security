package org.opensearch.security.filter;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.tuple.Triple;
import io.netty.handler.codec.http.HttpRequest;

public class NettyRequestChannel extends NettyRequest implements SecurityRequestChannel {

    private final AtomicReference<Triple<Integer, Map<String, String>, String>> completedResult = new AtomicReference<>(); 
    NettyRequestChannel(final HttpRequest request) {
        super(request);
    }

    @Override
    public boolean hasCompleted() {
        return completedResult.get() != null;
    }

    @Override
    public boolean completeWithResponse(int statusCode, Map<String, String> headers, String body) {
        if (hasCompleted()) {
            throw new UnsupportedOperationException("This channel has already completed");
        }

        completedResult.set(Triple.of(statusCode, headers, body));

        return true;
    }

    /** Accessor to get the completed response */
    public Triple<Integer, Map<String, String>, String> getCompletedRequest() {
        return completedResult.get();
    }
}
