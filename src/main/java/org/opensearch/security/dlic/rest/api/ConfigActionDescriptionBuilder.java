
package org.opensearch.security.dlic.rest.api;

import java.util.Objects;

public class ConfigActionDescriptionBuilder<T> {
    private String route;
    private String permission;
    private String configPath;
    private T defaultValue;

    public ConfigActionDescriptionBuilder() {
    }

    public ConfigActionDescriptionBuilder<T> route(final String route) {
        this.route = route;
        return this;
    }

    public ConfigActionDescriptionBuilder<T> permission(final String permission) {
        this.permission = permission;
        return this;
    }

    public ConfigActionDescriptionBuilder<T> configPath(final String configPath) {
        this.configPath = configPath;
        return this;
    }

    public ConfigActionDescriptionBuilder<T> onDeleteDefaultValue(final T defaultValue) {
        this.defaultValue = defaultValue;
        return this;
    }

    public ConfigActionDescription<T> build() {
        
        Objects.requireNonNull(this.route);
        // TODO: Ensure only valid route patterns
        // TODO: Ensure prefixes / route conventions
        
        Objects.requireNonNull(this.permission);
        // TODO: Ensure [A-Za-z.] characters
        // TODO: Endsure prefixes / namespacing convensions
        
        Objects.requireNonNull(this.configPath);
        // TODO: Can this be checked against the config?

        return new ConfigActionDescription<T>(this.route, this.permission, this.configPath, this.defaultValue);
    }
}