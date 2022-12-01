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
import java.util.regex.Pattern;

import com.google.common.io.BaseEncoding;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.OpenSearchException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.security.user.User;

import org.opensearch.security.support.Base64Helper.PackageBehavior;
import static org.opensearch.security.support.Base64Helper.deserializeObject;
import static org.opensearch.security.support.Base64Helper.serializeObject;

public class Base64HelperTest {

    private static final class NotSafeSerializable implements Serializable {
        private static final long serialVersionUID = 5135559266828470092L;
    }

    private static Serializable ds(Serializable s, PackageBehavior packageBehavior) {
        return deserializeObject(serializeObject(s, packageBehavior));
    }

    @Test
    public void testString() {
        String string = "string";
        Assert.assertEquals(string, ds(string, PackageBehavior.NONE));
    }

    @Test
    public void testInteger() {
        Integer integer = Integer.valueOf(0);
        Assert.assertEquals(integer, ds(integer, PackageBehavior.NONE));
    }

    @Test
    public void testDouble() {
        Double number = Double.valueOf(0.);
        Assert.assertEquals(number, ds(number, PackageBehavior.NONE));
    }

    @Test
    public void testInetSocketAddress() {
        InetSocketAddress inetSocketAddress = new InetSocketAddress(0);
        Assert.assertEquals(inetSocketAddress, ds(inetSocketAddress, PackageBehavior.NONE));
    }

    @Test
    public void testPattern() {
        Pattern pattern = Pattern.compile(".*");
        Assert.assertEquals(pattern.pattern(), ((Pattern) ds(pattern, PackageBehavior.NONE)).pattern());
    }

    @Test
    public void testUser() {
        User user = new User("user");
        Assert.assertEquals(user, ds(user, PackageBehavior.NONE));
    }

    @Test
    public void testSourceFieldsContext() {
        SourceFieldsContext sourceFieldsContext = new SourceFieldsContext(new SearchRequest(""));
        Assert.assertEquals(sourceFieldsContext.toString(), ds(sourceFieldsContext, PackageBehavior.NONE).toString());
    }

    @Test
    public void testHashMap() {
        HashMap map = new HashMap();
        Assert.assertEquals(map, ds(map, PackageBehavior.NONE));
    }

    @Test
    public void testArrayList() {
        ArrayList list = new ArrayList();
        Assert.assertEquals(list, ds(list, PackageBehavior.NONE));
    }

    @Test(expected = OpenSearchException.class)
    public void notSafeSerializable() {
        serializeObject(new NotSafeSerializable(), PackageBehavior.NONE);
    }

    @Test
    public void testStringWithRewriteOdfePackage() {
        String string = "string";
        Assert.assertEquals(string, ds(string, PackageBehavior.REWRITE_AS_ODFE));
    }

    @Test
    public void testIntegerWithRewriteOdfePackage() {
        Integer integer = Integer.valueOf(0);
        Assert.assertEquals(integer, ds(integer, PackageBehavior.REWRITE_AS_ODFE));
    }

    @Test
    public void testDoubleWithRewriteOdfePackage() {
        Double number = Double.valueOf(0.);
        Assert.assertEquals(number, ds(number, PackageBehavior.REWRITE_AS_ODFE));
    }

    @Test
    public void testInetSocketAddressWithRewriteOdfePackage() {
        InetSocketAddress inetSocketAddress = new InetSocketAddress(0);
        Assert.assertEquals(inetSocketAddress, ds(inetSocketAddress, PackageBehavior.REWRITE_AS_ODFE));
    }

    @Test
    public void testPatternWithRewriteOdfePackage() {
        Pattern pattern = Pattern.compile(".*");
        Assert.assertEquals(pattern.pattern(), ((Pattern) ds(pattern, PackageBehavior.REWRITE_AS_ODFE)).pattern());
    }

    @Test
    public void testUserWithRewriteOdfePackage() {
        User user = new User("user");
        Assert.assertEquals(user, ds(user, PackageBehavior.REWRITE_AS_ODFE));
    }

    @Test
    public void testSourceFieldsContextWithRewriteOdfePackage() {
        SourceFieldsContext sourceFieldsContext = new SourceFieldsContext(new SearchRequest(""));
        Assert.assertEquals(sourceFieldsContext.toString(), ds(sourceFieldsContext, PackageBehavior.REWRITE_AS_ODFE).toString());
    }

    @Test
    public void testHashMapWithRewriteOdfePackage() {
        HashMap map = new HashMap();
        Assert.assertEquals(map, ds(map, PackageBehavior.REWRITE_AS_ODFE));
    }

    @Test
    public void testArrayListWithRewriteOdfePackage() {
        ArrayList list = new ArrayList();
        Assert.assertEquals(list, ds(list, PackageBehavior.REWRITE_AS_ODFE));
    }

    @Test(expected = OpenSearchException.class)
    public void notSafeSerializableWithRewriteOdfePackage() {
        serializeObject(new NotSafeSerializable(), PackageBehavior.REWRITE_AS_ODFE);
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
