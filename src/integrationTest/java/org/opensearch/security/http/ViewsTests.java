/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.http;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.runner.RunWith;

import org.opensearch.client.Client;
import org.opensearch.test.framework.RolesMapping;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.apache.http.HttpStatus.SC_CREATED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ViewsTests {
    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").backendRoles("admin");
    private static final TestSecurityConfig.User VIEW_USER = new TestSecurityConfig.User("view_user");

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().singleNode()
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, VIEW_USER)
        .rolesMapping(new RolesMapping(ALL_ACCESS).backendRoles("admin"))
        .build();

    @BeforeClass
    public static void createTestData() {
        try (final Client client = cluster.getInternalNodeClient()) {
            client.prepareIndex("songs-2022").setRefreshPolicy(IMMEDIATE).setSource(SONGS[0].asMap()).get();
            client.prepareIndex("songs-2023").setRefreshPolicy(IMMEDIATE).setSource(SONGS[1].asMap()).get();
        }
    }

    public void createView() {
        try (
            final TestRestClient adminClient = cluster.getRestClient(ADMIN_USER);
            final TestRestClient viewClient = cluster.getRestClient(VIEW_USER)
        ) {

            final HttpResponse getAllViews = adminClient.get("/views");
            assertThat("No views have been created yet", getAllViews.getIntFromJsonBody("/views/count"), equalTo(0));

            final HttpResponse createView = adminClient.postJson("/views", createViewBody());
            createView.assertStatusCode(SC_CREATED);

            final HttpResponse searchView = adminClient.postJson("/views/songs/_search", createQueryString());
            assertThat(searchView.getIntFromJsonBody("/hits/total/value"), equalTo("2"));
        }
    }

    private String createQueryString() {
        return "{\n"
            + "    \"query\": {\n"
            + "        \"match_all\": {}\n"
            + "    },\n"
            + "    \"sort\": {\n"
            + "        \"title\": {\n"
            + "            \"order\": \"asc\"\n"
            + "        }\n"
            + "    }\n"
            + "}";
    }

    private String createViewBody() {
        return "{\n"
            + "    \"name\": \"songs\",\n"
            + "    \"description\": \"like imdb but smaller for songs\",\n"
            + "    \"targets\": [\n"
            + "        {\n"
            + "            \"indexPattern\": \"songs-2023, songs-2022\"\n"
            + "        }\n"
            + "    ]\n"
            + "}";
    }
}
