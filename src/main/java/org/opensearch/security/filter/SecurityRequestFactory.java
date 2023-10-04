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

package org.opensearch.security.filter;

import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;

/**
 * Generates wrapped versions of requests for use in the security plugin
 */
public class SecurityRequestFactory {

    /** Creates a security requset from a RestRequest */
    public static SecurityRequest from(final RestRequest request) {
        return new OpenSearchRequest(request);
    }

    /** Creates a security request channel from a RestRequest & RestChannel */
    public static SecurityRequestChannel from(final RestRequest request, final RestChannel channel) {
        return new OpenSearchRequestChannel(request, channel);
    }
}
