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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.oneOf;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent.MapParams;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

//./gradlew integrationTest --tests org.opensearch.security.MaskingTests
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class MaskingTests {

    private enum TestRoles {
        ROLE_WITH_NO_MASKING,
        MASKING_RANDOM_STRING,
        MASKING_RANDOM_LONG,
        MASKING_LOW_REPEAT_VALUE;
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
        .roles(new TestSecurityConfig.Role(TestRoles.ROLE_WITH_NO_MASKING.name())
                .clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .on("*"),
            new TestSecurityConfig.Role(TestRoles.MASKING_RANDOM_STRING.name())
                .clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .maskedFields("guid")
                .on("*"),
            new TestSecurityConfig.Role(TestRoles.MASKING_RANDOM_LONG.name())
                .clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .maskedFields("longId")
                .on("*"),
            new TestSecurityConfig.Role(TestRoles.MASKING_LOW_REPEAT_VALUE.name())
                .clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .maskedFields("genre")
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
        removeRolesFromReader();
    }
    
    private void removeRolesFromReader() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            for (TestRoles role : TestRoles.values()) {
                final String path = "_plugins/_security/api/rolesmapping/" + role.name();
                final HttpResponse response = client.delete(path);
                assertThat(response.getStatusCode(), oneOf(200, 204, 404));
            }
        }
    }

    @Test
    public void testMaskingBaslineScenarios() throws Exception {
        final Callable<Void> check = () -> {
            final long startMs = System.currentTimeMillis();

            final SearchSourceBuilder ssb = new SearchSourceBuilder();
            ssb.size(0);

            queryAndGetStats(ADMIN_USER, ssb);
            queryAndGetStats(READER, ssb);

            removeRolesFromReader();
            attachRoleToReader(TestRoles.ROLE_WITH_NO_MASKING);
            queryAndGetStats(READER, ssb);

            removeRolesFromReader();
            attachRoleToReader(TestRoles.MASKING_LOW_REPEAT_VALUE);
            queryAndGetStats(READER, ssb);

            removeRolesFromReader();
            attachRoleToReader(TestRoles.MASKING_RANDOM_LONG);
            queryAndGetStats(READER, ssb);

            removeRolesFromReader();
            attachRoleToReader(TestRoles.MASKING_RANDOM_STRING);
            queryAndGetStats(READER, ssb);

            final long endMs = System.currentTimeMillis() - startMs;
            System.out.println("Finished checks in " + endMs + "ms");

            return null;
        };

        createIndices(1, 50);
        check.call();

        setup();
        createIndices(1, 50 * 100);
        check.call();

        setup();
        createIndices(3, 50 * 100);
        check.call();

        setup();
        createIndices(3, 50 * 100 * 10);
        check.call();
    }

    @Test
    public void testMaskingAggregateFilterScenarios() throws Exception {
        final Callable<Void> check = () -> {
            final long startMs = System.currentTimeMillis();

            SearchSourceBuilder ssb = new SearchSourceBuilder();
            ssb.aggregation(AggregationBuilders.filters("my-filter", QueryBuilders.queryStringQuery("last")));
            ssb.aggregation(AggregationBuilders.count("counting").field("genre.keyword"));
            ssb.aggregation(AggregationBuilders.avg("averaging").field("longId"));
            ssb.size(0);

            queryAndGetStats(ADMIN_USER, ssb);
            queryAndGetStats(READER, ssb);

            removeRolesFromReader();
            attachRoleToReader(TestRoles.ROLE_WITH_NO_MASKING);
            queryAndGetStats(READER, ssb);

            removeRolesFromReader();
            attachRoleToReader(TestRoles.MASKING_LOW_REPEAT_VALUE);
            queryAndGetStats(READER, ssb);

            removeRolesFromReader();
            attachRoleToReader(TestRoles.MASKING_RANDOM_LONG);
            queryAndGetStats(READER, ssb);

            removeRolesFromReader();
            attachRoleToReader(TestRoles.MASKING_RANDOM_STRING);
            queryAndGetStats(READER, ssb);

            final long endMs = System.currentTimeMillis() - startMs;
            System.out.println("Finished checks in " + endMs + "ms");

            return null;
        };

        createIndices(1, 50);
        check.call();

        setup();
        createIndices(1, 50 * 100);
        check.call();

        setup();
        createIndices(3, 50 * 100);
        check.call();

        setup();
        createIndices(3, 50 * 100 * 10);
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

    private void createIndices(final int count, final int docCount) throws IOException {
        System.out.println("Creating " + count + " indices with " + docCount + " documents");
        final long currentTimeMillis = System.currentTimeMillis();
        try (Client client = cluster.getInternalNodeClient()) {
            final ExecutorService pool = Executors.newFixedThreadPool(25);
            final List<CompletableFuture<Void>> futures = IntStream.range(1, count + 1).mapToObj(n -> {
                final String indexName = INDEX_NAME_PREFIX + n;
                final Random random = new Random();
                return CompletableFuture.runAsync(() -> {
                    var docs = new ArrayList<IndexRequest>();
                    final Map<String, Object> baseDoc = new HashMap(SONGS[0].asMap());
                    for (int i = 0; i < docCount - 1; i++) {
                        var uuid = UUID.randomUUID().toString();
                        baseDoc.put("guid", uuid);
                        baseDoc.put("longId", random.nextLong());
                        docs.add(new IndexRequest().index(indexName).id(uuid).source(baseDoc));
                    }

                    for (int indexReqGroupN = 0; indexReqGroupN < docCount / 250; indexReqGroupN++) {
                        BulkRequest br = new BulkRequest();
                        docs.stream().skip(n * 250).limit(250).forEach(ir -> {
                            br.add(ir);
                        });

                        if (br.numberOfActions() != 0) {
                            client.bulk(br).actionGet();
                        }
                    }
                }, pool);
            }).collect(Collectors.toList());

            final CompletableFuture<Void> futuresCompleted = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
            futuresCompleted.join();
        }
        System.out.println("Creation completed, " + (System.currentTimeMillis() - currentTimeMillis) + "ms");
    }

    private void queryAndGetStats(final TestSecurityConfig.User user, final SearchSourceBuilder searchSourceBuilder) throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(user)) {
            final int samplesToIgnore = 5;
            final int samples = 100 + samplesToIgnore;
            int attempts = 0;
            final List<Long> results = new ArrayList<>();
            for (int i = 0; i < samples; i++) {
                final var rt1 = Runtime.getRuntime();
                final long start_used = rt1.totalMemory() - rt1.freeMemory();

                SearchRequest request = new SearchRequest(INDEX_NAME_PREFIX + "*");
                request.source(searchSourceBuilder);

                final SearchResponse response = restHighLevelClient.search(request, DEFAULT);
                if (i == 0) {
                    try (final XContentBuilder builder = XContentFactory.jsonBuilder()) {
                        response.toXContent(builder, new MapParams(Map.of("a","b")));
                        System.err.println("Response " + builder.toString());
                    }
                }

                final var rt2 = Runtime.getRuntime();
                final long end_used = rt2.totalMemory() - rt2.freeMemory();

                final long delta = end_used - start_used;
                attempts++;
                if (delta < 0) {
                    // ignore negitive values - GC was run and it would pollute the results
                    i--;
                } else {
                    results.add(delta);
                }
            }
            // toss out inital samples
            IntStream.range(0, samplesToIgnore).forEach(n -> results.remove(0));

            System.out.println("User, Count, Attempts, Avg, Max, Min, Std Heap Used delta bytes:" + 
                user.getName() +
                ", " + results.size() +
                ", " + attempts +
                ", " + String.format("%,f", results.stream().mapToLong(a -> a).average().getAsDouble()) +
                ", " + String.format("%,d", results.stream().mapToLong(a -> a).max().getAsLong()) +
                ", " + String.format("%,d", results.stream().mapToLong(a -> a).min().getAsLong()) +
                ", " + String.format("%,.2f", calcStd(results)));
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
