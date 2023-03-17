/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.dlic.dlsfls;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.StringContains.containsString;

public class FlsIndexingTests extends AbstractDlsFlsTest {

    protected void populateData(final Client tc) {
        // Create several documents in different indices with shared field names,
        // different roles will have different levels of FLS restrictions
        tc.index(new IndexRequest("yellow-pages").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"phone-all\":1001,\"phone-some\":1002,\"phone-one\":1003}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("green-pages").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"phone-all\":2001,\"phone-some\":2002,\"phone-one\":2003}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("blue-book").id("3").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"phone-all\":3001,\"phone-some\":3002,\"phone-one\":3003}", XContentType.JSON)).actionGet();

            // Seperate index used to test aliasing
        tc.index(new IndexRequest(".hidden").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{}", XContentType.JSON)).actionGet();
    }

    private Header asPhoneOneUser = encodeBasicHeader("user_aaa", "password");
    private Header asPhoneSomeUser = encodeBasicHeader("user_bbb", "password");
    private Header asPhoneAllUser = encodeBasicHeader("user_ccc", "password");

    private final String searchQuery = "/*/_search?filter_path=hits.hits&pretty";

    @Test
    public void testSingleIndexFlsApplied() throws Exception {
        setup();

        HttpResponse res = rh.executeGetRequest("/_plugins/_security/config/tenancy/multitenancyEnabled", encodeBasicHeader("admin", "admin"));
        System.err.println("STATUS: \r\n" + res.getStatusCode() + " " + res.getStatusReason());
        System.err.println("BODY:\r\n"+ res.getBody());
    }
}
