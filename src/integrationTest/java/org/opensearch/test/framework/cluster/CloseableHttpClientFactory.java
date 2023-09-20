/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.cluster;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

class CloseableHttpClientFactory {

    private final SSLContext sslContext;

    private final RequestConfig requestConfig;

    private final HttpRoutePlanner routePlanner;

    private final String[] supportedCipherSuit;

    public CloseableHttpClientFactory(
        SSLContext sslContext,
        RequestConfig requestConfig,
        HttpRoutePlanner routePlanner,
        String[] supportedCipherSuit
    ) {
        this.sslContext = Objects.requireNonNull(sslContext, "SSL context is required.");
        this.requestConfig = requestConfig;
        this.routePlanner = routePlanner;
        this.supportedCipherSuit = supportedCipherSuit;
    }

    public CloseableHttpClient getHTTPClient() {

        final HttpClientBuilder hcb = HttpClients.custom();

        final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            this.sslContext,
            null,
            supportedCipherSuit,
            NoopHostnameVerifier.INSTANCE
        );

        final HttpClientConnectionManager cm = new PoolingHttpClientConnectionManager();
        /** TODO: HOW SHOULD THIS BE REPLACED ??? */
        // final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
        //     .setSSLSocketFactory(sslsf)
        //     .setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(60, TimeUnit.SECONDS).build())
        //     .build();
        hcb.setConnectionManager(cm);
        if (routePlanner != null) {
            hcb.setRoutePlanner(routePlanner);
        }

        if (requestConfig != null) {
            hcb.setDefaultRequestConfig(requestConfig);
        }

        return hcb.build();
    }
}
