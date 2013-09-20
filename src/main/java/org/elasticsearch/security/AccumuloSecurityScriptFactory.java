package org.elasticsearch.security;

import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.component.AbstractComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.script.ExecutableScript;
import org.elasticsearch.script.NativeScriptFactory;

import java.util.Map;

public class AccumuloSecurityScriptFactory extends AbstractComponent implements NativeScriptFactory {

    @Inject
    public AccumuloSecurityScriptFactory(Settings settings) {
        super(settings);
    }

    @Override
    public ExecutableScript newScript(@Nullable Map<String, Object> params) {
        return new AccumuloVisibilityFilter(params, this.logger);
    }
}