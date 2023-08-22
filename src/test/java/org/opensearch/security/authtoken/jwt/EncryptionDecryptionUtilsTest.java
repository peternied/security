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

package org.opensearch.security.authtoken.jwt;

import org.junit.Assert;
import org.junit.Test;
import java.util.Base64;

public class EncryptionDecryptionUtilsTest {

    @Test
    public void testEncryptDecrypt() {
        String secret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());
        String data = "Hello, OpenSearch!";

        String encryptedString = EncryptionDecryptionUtil.encrypt(secret, data);
        String decryptedString = EncryptionDecryptionUtil.decrypt(secret, encryptedString);

        Assert.assertEquals(data, decryptedString);
    }

    @Test
    public void testDecryptingWithWrongKey() {
        String secret1 = Base64.getEncoder().encodeToString("correctKey12345".getBytes());
        String secret2 = Base64.getEncoder().encodeToString("wrongKey1234567".getBytes());
        String data = "Hello, OpenSearch!";

        String encryptedString = EncryptionDecryptionUtil.encrypt(secret1, data);

        RuntimeException ex = Assert.assertThrows(RuntimeException.class, () -> EncryptionDecryptionUtil.decrypt(secret2, encryptedString));

        Assert.assertEquals("The cipher was unable to perform pass over data", ex.getMessage());
    }

    @Test
    public void testDecryptingCorruptedData() {
        String secret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());
        String corruptedEncryptedString = "corruptedData";

        RuntimeException ex = Assert.assertThrows(
            RuntimeException.class,
            () -> EncryptionDecryptionUtil.decrypt(secret, corruptedEncryptedString)
        );

        Assert.assertEquals("Last unit does not have enough valid bits", ex.getMessage());
    }

    @Test
    public void testEncryptDecryptEmptyString() {
        String secret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());
        String data = "";

        String encryptedString = EncryptionDecryptionUtil.encrypt(secret, data);
        String decryptedString = EncryptionDecryptionUtil.decrypt(secret, encryptedString);

        Assert.assertEquals(data, decryptedString);
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullValue() {
        String secret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());
        String data = null;

        EncryptionDecryptionUtil.encrypt(secret, data);
    }

    @Test(expected = NullPointerException.class)
    public void testDecryptNullValue() {
        String secret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());
        String data = null;

        EncryptionDecryptionUtil.decrypt(secret, data);
    }
}
