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

package org.opensearch.security.auditlog.compliance;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl.MessagesNotFoundException;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThrows;

public class RestApiComplianceAuditlogTest extends AbstractAuditlogiUnitTest {

    @Test
    public void testRestApiRolesEnabled() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();

        setup(additionalSettings);
        TestAuditlogImpl.doThenWaitForMessage(() -> {
            final String body = "{ \"password\":\"test\",\"backend_roles\":[\"role1\",\"role2\"] }";
            final HttpResponse response = rh.executePutRequest("_opendistro/_security/api/internalusers/compuser?pretty", body, encodeBasicHeader("admin", "admin"));
            Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        });
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("audit_request_effective_user"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_READ"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("UPDATE"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testRestApiRolesDisabled() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();

        setup(additionalSettings);
        final String body = "{ \"password\":\"test\",\"backend_roles\":[\"role1\",\"role2\"] }";

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        TestAuditlogImpl.doThenWaitForMessage(() -> {
            final HttpResponse response = rh.executePutRequest("_opendistro/_security/api/internalusers/compuser?pretty", body);
            Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        });
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("audit_request_effective_user"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_READ"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("UPDATE"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    @Ignore
    public void testRestApiRolesDisabledGet() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();

        setup(additionalSettings);

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";
        TestAuditlogImpl.doThenWaitForMessages(() -> {
            final HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/rolesmapping/opendistro_security_all_access?pretty");
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        }, 2);
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("audit_request_effective_user"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_READ"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("UPDATE"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }



    @Test
    public void testAutoInit() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();

        TestAuditlogImpl.doThenWaitForMessages(() -> {
            try {
                setup(additionalSettings);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }, 4);

        Assert.assertTrue(TestAuditlogImpl.messages.size() > 2);
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("audit_request_effective_user"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_EXTERNAL_CONFIG"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testRestApiNewUser() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, "admin")
                .build();

        setup(additionalSettings);
        final MessagesNotFoundException ex1 = assertThrows(MessagesNotFoundException.class, () -> {
            TestAuditlogImpl.doThenWaitForMessage(() -> {
                final String body = "{ \"password\":\"test\",\"backend_roles\":[\"role1\",\"role2\"] }";
                final HttpResponse response = rh.executePutRequest("_opendistro/_security/api/internalusers/compuser?pretty", body, encodeBasicHeader("admin", "admin"));
                Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
            });
        });
        assertThat(ex1.getMissingCount(), equalTo(1));
    }

    @Test
    public void testRestInternalConfigRead() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();

        setup(additionalSettings);

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";
        TestAuditlogImpl.doThenWaitForMessage(() -> {
            final HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/internalusers/admin?pretty");
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        });
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("audit_request_effective_user"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_READ"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("UPDATE"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testBCryptHashRedaction() throws Exception {
        final Settings settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
                .build();
        setup(settings);
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        // read internal users and verify no BCrypt hash is present in audit logs
        TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers");
        });
        Assert.assertFalse(AuditMessage.BCRYPT_HASH.matcher(TestAuditlogImpl.sb.toString()).matches());

        // read internal user worf and verify no BCrypt hash is present in audit logs
        TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers/worf");
        });
        Assert.assertFalse(AuditMessage.BCRYPT_HASH.matcher(TestAuditlogImpl.sb.toString()).matches());

        // create internal user and verify no BCrypt hash is present in audit logs
        TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executePutRequest("/_opendistro/_security/api/internalusers/test",  "{ \"password\":\"test\"}");
        });
        Assert.assertFalse(AuditMessage.BCRYPT_HASH.matcher(TestAuditlogImpl.sb.toString()).matches());
    }
}
