/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.concurrent.Callable;


import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.test.framework.AsyncActions;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.either;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.oneOf;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

//./gradlew integrationTest --tests org.opensearch.security.DlsTests
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DlsTests {

    private enum TestRoles {
        EMPTY_DLS,
        DLS_ONLY_ROCK,
        DLS_ONLY_JAZZ,
        DLS_ONLY_ROCK_AND_JAZZ,
        DLS_ONLY_LONG_VALUE;
    }

    static final String INDEX_NAME_PREFIX = "test-index-";
    static final String ALL_INDICES_ALIAS = "_all";
    static final String READER_BACKEND_ROLE = "ber-reader";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    /**
    * User who is allowed to see all fields on all indices. Values of the title and artist fields should be masked.
    */
    static final TestSecurityConfig.User READER = new TestSecurityConfig.User("reader")
        .roles(
            new TestSecurityConfig.Role("read-everything")
                .clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .on("*")
        ).backendRoles(READER_BACKEND_ROLE);

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of("plugins.security.restapi.roles_enabled", List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()))
        )
        .roles(new TestSecurityConfig.Role(TestRoles.EMPTY_DLS.name())
                .clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls("")
                .on("*"),
            new TestSecurityConfig.Role(TestRoles.DLS_ONLY_ROCK.name())
                .clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls("{\"bool\":{\"must\":[{\"terms\":{\"genre.keyword\":[\"rock\"]}}]}}")
                .on("*"),
            new TestSecurityConfig.Role(TestRoles.DLS_ONLY_JAZZ.name())
                .clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls("{\"bool\":{\"must\":[{\"terms\":{\"genre.keyword\":[\"jazz\"]}}]}}")
                .on("*"),
            new TestSecurityConfig.Role(TestRoles.DLS_ONLY_LONG_VALUE.name())
                .clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls("{\"bool\":{\"must\":[{\"terms\":{\"genre.keyword\":[\""
                 + "0123456789".repeat(100) // ==1000 characters
                 +   "\"]}}]}}")
                .on("*"),
            new TestSecurityConfig.Role(TestRoles.DLS_ONLY_ROCK_AND_JAZZ.name())
                .clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls("{\"bool\":{\"must\":[{\"terms\":{\"genre.keyword\":[\"jazz\"]}},{\"terms\":{\"genre.keyword\":[\"rock\"]}}]}}")
                .on("*"))
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(
            ADMIN_USER,
            READER
        )
        .build();

    @BeforeClass
    public static void createTestData() {
    }

    @Before
    public void setup() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            for (TestRoles role : TestRoles.values()) {
                final String path = "_plugins/_security/api/rolesmapping/" + role.name();
                final HttpResponse response = client.delete(path);
                assertThat(response.getStatusCode(), oneOf(200, 204, 404));
            }
        }
        // try (Client client = cluster.getInternalNodeClient()) {
        //     client.admin().indices()
        // }
    }

    @Test
    public void testBaselinedDlsScenarios() throws Exception {
        final Callable<Void> check = () -> {
            final long startMs = System.currentTimeMillis();
            queryAndGetStats(ADMIN_USER);
            queryAndGetStats(READER);

            attachRoleToReader(TestRoles.EMPTY_DLS);
            queryAndGetStats(READER);

            attachRoleToReader(TestRoles.DLS_ONLY_ROCK);
            queryAndGetStats(READER);

            attachRoleToReader(TestRoles.DLS_ONLY_JAZZ);
            queryAndGetStats(READER);
            final long endMs = System.currentTimeMillis() - startMs;
            System.out.println("Finished checks in " + endMs + "ms");

            return null;
        };
        createIndices(5);
        check.call();

        setup();
        createIndices(50);
        check.call();

        setup();
        createIndices(100);
        check.call();
    }

    @Test
    public void testConsolidatedDlsScenarios() throws Exception {
        final Callable<Void> check = () -> {
            final long startMs = System.currentTimeMillis();
            queryAndGetStats(ADMIN_USER);
            queryAndGetStats(READER);

            attachRoleToReader(TestRoles.DLS_ONLY_ROCK_AND_JAZZ);
            queryAndGetStats(READER);
            final long endMs = System.currentTimeMillis() - startMs;
            System.out.println("Finished checks in " + endMs + "ms");
            return null;
        };
        createIndices(5);
        check.call();

        setup();
        createIndices(50);
        check.call();

        setup();
        createIndices(100);
        check.call();
    }

    @Test
    public void testDlsLargerQueryScenarios() throws Exception {
        final Callable<Void> check = () -> {
            final long startMs = System.currentTimeMillis();
            queryAndGetStats(ADMIN_USER);
            queryAndGetStats(READER);

            attachRoleToReader(TestRoles.DLS_ONLY_LONG_VALUE);
            queryAndGetStats(READER);
            final long endMs = System.currentTimeMillis() - startMs;
            System.out.println("Finished checks in " + endMs + "ms");
            return null;
        };
        createIndices(5);
        check.call();

        setup();
        createIndices(50);
        check.call();

        setup();
        createIndices(100);
        check.call();
    }

    private void attachRoleToReader(final TestRoles role) {
        System.out.println("Attached READER with role " + role);
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            final String path = "_plugins/_security/api/rolesmapping/" + role;
            final String body = String.format("{\"backend_roles\": [\"%s\"]}", READER_BACKEND_ROLE);
            final HttpResponse response = client.putJson(path, body);
            response.assertStatusCode(201);
        }
    }

    private void createIndices(final int count) throws IOException {
        System.out.println("Creating " + count + " indices with 1 document");
        try (Client client = cluster.getInternalNodeClient()) {
            final ExecutorService pool = Executors.newFixedThreadPool(25);
            final List<CompletableFuture<Void>> futures = IntStream.range(1, count).mapToObj(n -> {
                final String indexName = INDEX_NAME_PREFIX + n;
                return CompletableFuture.runAsync(() -> client.prepareIndex().setIndex(indexName).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0].asMap()).get(), pool);
            }).collect(Collectors.toList());

            final CompletableFuture<Void> futuresCompleted = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
            futuresCompleted.join();
        }
    }

    private void queryAndGetStats(final TestSecurityConfig.User user) throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(user)) {
            final int samplesToIgnore = 5;
            final int samples = 100 + samplesToIgnore;
            final List<Long> results = new ArrayList<>();
            for (int i = 0; i < samples; i++) {
                final long start = System.currentTimeMillis();
                final SearchResponse response = restHighLevelClient.search(new SearchRequest(INDEX_NAME_PREFIX + "*"), DEFAULT);
                final long endMs = System.currentTimeMillis() - start;
                results.add(endMs);
            }
            // toss out inital samples
            IntStream.range(0, samplesToIgnore).forEach(n -> results.remove(0));

            System.out.println("User, Count, Avg, Max, Min, Std ms " + 
                user.getName() +
                ", " + results.size() +
                ", " + results.stream().mapToLong(a -> a).average().getAsDouble() +
                ", " + results.stream().mapToLong(a -> a).max().getAsLong() +
                ", " + results.stream().mapToLong(a -> a).min().getAsLong() +
                ", " + String.format("%.2f", calcStd(results)) + "\r\n");
        }
    }

    private static double calcStd(final List<Long> numbers) {
        final Double mean= numbers.stream()
            .mapToDouble(Long::doubleValue)
            .average()
            .orElse(0);
        final double variance = numbers.stream()
            .mapToDouble(i -> Math.pow(i - mean, 2))
            .average()
            .orElse(0);
        return Math.sqrt(variance);
    }

}
