
package org.opensearch.security.dlic.rest.api;

import java.util.Objects;

public class ConfigActionDescription<T> {
    private final String route;
    private final String permission;
    private final String configPath;
    private final T defaultValue;

    ConfigActionDescription(
        final String route,
        final String permission,
        final String configPath,
        final T defaultValue
    ) {
        this.route = route;
        this.permission = permission;
        this.configPath = configPath;
        this.defaultValue = defaultValue;
    }

    public String getRoute() { return this.route; }
    public String getPermission() { return this.permission; }
    public String getConfigPath() { return this.configPath; }
    public T getDefaultValue() { return this.defaultValue; }
}
