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
import org.junit.Test;
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
    private static final TestSecurityConfig.User VIEW_USER = new TestSecurityConfig.User("view_user").roles(new TestSecurityConfig.Role("see views").clusterPermissions("cluster:views:search"));

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().singleNode()
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, VIEW_USER)
        .rolesMapping(new RolesMapping(ALL_ACCESS).backendRoles("admin"))
        .build();

    @BeforeClass
    public static void createTestData() {
        try (final Client client = cluster.getInternalNodeClient()) {
            final var doc1 = client.prepareIndex("songs-2022").setRefreshPolicy(IMMEDIATE).setSource(SONGS[0].asMap()).get();
            System.err.println("Created doc1:\r\n" + doc1);
            final var doc2 = client.prepareIndex("songs-2023").setRefreshPolicy(IMMEDIATE).setSource(SONGS[1].asMap()).get();
            System.err.println("Created doc2:\r\n" + doc2);
        }
    }

    @Test
    public void createView() {
        try (
            final TestRestClient adminClient = cluster.getRestClient(ADMIN_USER);
            final TestRestClient viewClient = cluster.getRestClient(VIEW_USER)
        ) {

            final HttpResponse getAllViews = adminClient.get("views");
            assertThat("No views have been created yet", getAllViews.getIntFromJsonBody("/views/count"), equalTo(0));

            final HttpResponse createView = adminClient.postJson("views", createViewBody());
            createView.assertStatusCode(SC_CREATED);
            System.err.println("View created:\r\n" + createView.getBody());

            final HttpResponse search = adminClient.postJson("songs-*/_search", createQueryString());
            System.err.println("Search result:\r\n" + search.getBody());

            final HttpResponse searchView = adminClient.postJson("views/songs/_search", createQueryString());
            assertThat("Search response was:\r\n" + searchView.getBody(), searchView.getIntFromJsonBody("/hits/total/value"), equalTo(2));

            final HttpResponse searchViewAsUser = viewClient.postJson("views/songs/_search", createQueryString());
            assertThat("Search response was:\r\n" + searchViewAsUser.getBody(), searchViewAsUser.getIntFromJsonBody("/hits/total/value"), equalTo(2));
        }
    }

    private String createQueryString() {
        return "{\n"
            + "    \"query\": {\n"
            + "        \"match_all\": {}\n"
            + "    },\n"
            + "    \"sort\": {\n"
            + "        \"title.keyword\": {\n"
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
            + "            \"indexPattern\": \"songs-2022\"\n"
            + "        },\n"
            + "        {\n"
            + "            \"indexPattern\": \"songs-2023\"\n"
            + "        }\n"
            + "    ]\n"
            + "}";
    }
}
