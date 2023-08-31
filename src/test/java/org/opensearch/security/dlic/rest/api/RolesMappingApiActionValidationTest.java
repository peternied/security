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

package org.opensearch.security.dlic.rest.api;

import org.junit.Before;
import org.junit.Test;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.securityconf.impl.CType;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doReturn;

public class RolesMappingApiActionValidationTest extends AbstractApiActionValidationTest {

    @Before
    public void setupRoles() throws Exception {
        setupRolesConfiguration();
    }

    @Test
    public void isAllowedRightsToChangeRoleEntity() throws Exception {
        when(restApiAdminPrivilegesEvaluator.isCurrentUserAdminFor(Endpoint.ROLESMAPPING)).thenReturn(true);
        final var rolesMappingApiActionEndpointValidator = new RolesMappingApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator();
        final var result = rolesMappingApiActionEndpointValidator.isAllowedToChangeImmutableEntity(
                SecurityConfiguration.of("rest_api_admin_role", configuration)
        );
        assertTrue(result.isValid());
    }

    @Test
    public void isNotAllowedNoRightsToChangeRoleEntity() throws Exception {
        when(restApiAdminPrivilegesEvaluator.isCurrentUserAdminFor(Endpoint.ROLESMAPPING)).thenReturn(false);
        when(restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();

         final var rolesApiActionEndpointValidator =
                 new RolesMappingApiAction(clusterService, threadPool,
                         securityApiDependencies).createEndpointValidator();
         final var result = rolesApiActionEndpointValidator.isAllowedToChangeImmutableEntity(
                 SecurityConfiguration.of("rest_api_admin_role", configuration));

         assertFalse(result.isValid());
         assertEquals(RestStatus.FORBIDDEN, result.status());
    }

    @Test
    public void onConfigChangeShouldCheckRoles() throws Exception {
        when(restApiAdminPrivilegesEvaluator.isCurrentUserAdminFor(Endpoint.ROLESMAPPING)).thenReturn(false);
        when(restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();
        doReturn(rolesConfiguration).when(configurationRepository).getConfigurationFromIndex(CType.ROLES, false);
        final var rolesApiActionEndpointValidator =
                new RolesMappingApiAction(clusterService, threadPool,
                        securityApiDependencies).createEndpointValidator();

        // no role
        var result = rolesApiActionEndpointValidator.onConfigChange(SecurityConfiguration.of("aaa", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.NOT_FOUND, result.status());
        //reserved role is not ok
        result = rolesApiActionEndpointValidator.onConfigChange(SecurityConfiguration.of("kibana_read_only", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.FORBIDDEN, result.status());
        //just regular_role
        result = rolesApiActionEndpointValidator.onConfigChange(SecurityConfiguration.of("regular_role", configuration));
        assertTrue(result.isValid());
    }

}
