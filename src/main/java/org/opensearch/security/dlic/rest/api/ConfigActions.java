package org.opensearch.security.dlic.rest.api;


import org.opensearch.action.ActionType;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionResponse;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import java.io.IOException;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import java.util.Map;
import java.util.HashMap;

public class ConfigActions {
    private Map<ActionType, Class> actions = new HashMap<>();

    public ConfigActions() {
        ConfigActionDescription multitenancyEnabled = new ConfigActionDescriptionBuilder<String>()
            .configPath("dynamic.multitenancy_enabled")
            .permission("securityconfig:admin/config/tenancy/multitenancyEnabled")
            .route("_plugins/_security/config/tenancy/multitenancyEnabled")
            .onDeleteDefaultValue("false")
            .build();

        register(multitenancyEnabled);
    }

    public Map<ActionType, Class> getActions(){
        return actions;
    } 

    public void register(ConfigActionDescription description) {
        final ActionType action = new ActionType<StringValueResponse>(
            description.getPermission(),
            in -> new StringValueResponse(in));

        // TODO: This is busted because we need an instanceof the transport service instead of nulls
        HandledTransportAction<?,?> transportAction = new HandledTransportAction<EmptyRequest, StringValueResponse>
            (description.getPermission(), null, null, in -> new EmptyRequest(in)) {
                @Override
                protected void doExecute(Task task, EmptyRequest request, ActionListener<StringValueResponse> listener) {
                }
            };

        actions.put(action, transportAction.getClass());
    }

    public static class EmptyRequest extends ActionRequest {
        public EmptyRequest(StreamInput in) throws IOException {
            super(in);
        }
        @Override
        public ActionRequestValidationException validate() {
            return null;
        }
    }
    public static class StringValueResponse extends ActionResponse {
        private String value;
        public StringValueResponse() {
            value = null;
        }
        public StringValueResponse(final StreamInput in) throws IOException {
            this.value = in.readString();
        }
        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            out.writeString(value);
        }
    }
}
