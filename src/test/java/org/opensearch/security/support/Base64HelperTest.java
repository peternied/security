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
package org.opensearch.security.support;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import com.google.common.io.BaseEncoding;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.OpenSearchException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.collect.List;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import static org.opensearch.security.support.Base64Helper.deserializeObject;
import static org.opensearch.security.support.Base64Helper.serializeObject;

public class Base64HelperTest {

    private static final class NotSafeSerializable implements Serializable {
        private static final long serialVersionUID = 5135559266828470092L;
    }

    private static Serializable ds(Serializable s) {
        return deserializeObject(serializeObject(s));
    }

    @Test
    public void testString() {
        String string = "string";
        Assert.assertEquals(string, ds(string));
    }

    @Test
    public void testInteger() {
        Integer integer = Integer.valueOf(0);
        Assert.assertEquals(integer, ds(integer));
    }

    @Test
    public void testDouble() {
        Double number = Double.valueOf(0.);
        Assert.assertEquals(number, ds(number));
    }

    @Test
    public void testInetSocketAddress() {
        InetSocketAddress inetSocketAddress = new InetSocketAddress(0);
        Assert.assertEquals(inetSocketAddress, ds(inetSocketAddress));
    }

    @Test
    public void testPattern() {
        Pattern pattern = Pattern.compile(".*");
        Assert.assertEquals(pattern.pattern(), ((Pattern) ds(pattern)).pattern());
    }

    @Test
    public void testUser() {
        User user = new User("user");
        Assert.assertEquals(user, ds(user));
    }

    /** This test spins up a thread to add entries to a map, rotating through all values  */
    @Test
    public void testUserSerializationSafe() {
        final AtomicInteger removedUserCount = new AtomicInteger(0);
        final AtomicBoolean keepRunning = new AtomicBoolean(true);
        final ConcurrentMap<Integer, User> userMap = new ConcurrentHashMap<Integer, User>();
        final int concurrentActions = 10; // Dial up/down for more collisions
        final ExecutorService pool = Executors.newFixedThreadPool(concurrentActions);
        final int usersSize = 100; // Dial up/down for smaller collision space and runtime.


        pool.submit(() -> {
            int i = 0;
            while (keepRunning.get()) {
                i++; if (i == usersSize) { i = 0; }
                final String userName = "Megan" + i;
                final User newUser = new User(
                    userName,
                    List.of("roleA", "roleB", "roleC" + (int)(Math.random()*100)),
                    new AuthCredentials(userName, "BackendRole1", "BackendRole2", "BackendRole3"));
                userMap.put(i, newUser);
            }
        });

        Runnable pickUserDeleter = () -> {
            while(keepRunning.get()) {
                try {
                    final int pickedUser = (int)(Math.random() * usersSize);
                    final User user = userMap.get(pickedUser);
                    if (user == null) {
                        continue;
                    }
                    ds(user);
                    userMap.remove(pickedUser);
                    removedUserCount.getAndIncrement();
                } catch (Exception e) {
                    System.out.println(e);
                    keepRunning.set(false);
                }
            }
        };

        for(int i = 0; i < concurrentActions - 1; i ++){
            pool.submit(pickUserDeleter);
        }

        while(keepRunning.get()) {
            try {
                Thread.sleep(100);
            } catch (Exception _e) {/* Ignored */}
            if (removedUserCount.get() >= 1000*usersSize) {
                keepRunning.set(false);
            }
        }
        System.out.println("Final number was " + removedUserCount.get());
    }

    @Test
    public void testSourceFieldsContext() {
        SourceFieldsContext sourceFieldsContext = new SourceFieldsContext(new SearchRequest(""));
        Assert.assertEquals(sourceFieldsContext.toString(), ds(sourceFieldsContext).toString());
    }

    @Test
    public void testHashMap() {
        HashMap map = new HashMap();
        Assert.assertEquals(map, ds(map));
    }

    @Test
    public void testArrayList() {
        ArrayList list = new ArrayList();
        Assert.assertEquals(list, ds(list));
    }

    @Test(expected = OpenSearchException.class)
    public void notSafeSerializable() {
        serializeObject(new NotSafeSerializable());
    }

    @Test(expected = OpenSearchException.class)
    public void notSafeDeserializable() throws Exception {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (final ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(new NotSafeSerializable());
        }
        deserializeObject(BaseEncoding.base64().encode(bos.toByteArray()));
    }
}
