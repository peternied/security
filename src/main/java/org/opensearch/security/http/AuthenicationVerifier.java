package org.opensearch.security.http;

import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.security.filter.NettyRequestChannel;
import org.opensearch.security.filter.SecurityRequestChannel;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.filter.SecurityRestFilter;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.ReferenceCountUtil;

public class AuthenticationVerifer extends ChannelInboundHandlerAdapter {

    final static Logger log = LogManager.getLogger(AuthenticationVerifer.class);

    private SecurityRestFilter restFilter;

    public AuthenticationVerifer(SecurityRestFilter restFilter) {
        this.restFilter = restFilter;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof HttpRequest)) {
            ctx.fireChannelRead(msg);
        }

        final HttpRequest request = (HttpRequest) msg;
        final Optional<FullHttpResponse> shouldResponse = getAuthenticationResponse(request);
        if (shouldResponse.isPresent()) {
            ctx.writeAndFlush(shouldResponse.get()).addListener(ChannelFutureListener.CLOSE);
        } else {
            // Let the request pass to the next channel handler
            ctx.fireChannelRead(msg);
        }
    }

    private Optional<FullHttpResponse> getAuthenticationResponse(HttpRequest request) {

        log.info("Checking if request is authenticated:\n" + request);

        final NettyRequestChannel requestChannel = (NettyRequestChannel) SecurityRequestFactory.from(request);
        restFilter.checkAndAuthenticateRequest(requestChannel);

        if (requestChannel.hasCompleted()) {
            final FullHttpResponse response = new DefaultFullHttpResponse(
                    request.protocolVersion(),
                    HttpResponseStatus.valueOf(requestChannel.getCompletedRequest().getLeft()),
                    Unpooled.copiedBuffer(requestChannel.getCompletedRequest().getRight().getBytes()));
            requestChannel.getCompletedRequest().getMiddle().forEach((key, value) -> response.headers().set(key, value));
            return Optional.of(response);
        }
        
        return Optional.empty();
    }

}
