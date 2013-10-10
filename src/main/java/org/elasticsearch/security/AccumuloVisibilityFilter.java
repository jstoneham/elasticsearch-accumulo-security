package org.elasticsearch.security;

import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.accumulo.core.security.VisibilityEvaluator;
import org.apache.accumulo.core.security.VisibilityParseException;
import org.apache.commons.collections.map.LRUMap;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.index.fielddata.ScriptDocValues;
import org.elasticsearch.script.AbstractSearchScript;

import java.util.List;
import java.util.Map;

public class AccumuloVisibilityFilter extends AbstractSearchScript {

    private final ESLogger logger;
    private final VisibilityEvaluator visibilityEvaluator;
    private final LRUMap cache = new LRUMap(1000);
    private String securityExpressionField = "securityExpression";

    public AccumuloVisibilityFilter(Map<String, Object> params, ESLogger logger) {
        this.logger = logger;

        if (params.get("expressionField") != null) {
            this.securityExpressionField = params.get("expressionField").toString();
        }

        String auths = params.get("auths").toString().trim();
        Authorizations authorizations;
        if (auths.isEmpty()) {
            authorizations = new Authorizations();
        } else {
            authorizations = new Authorizations(auths.split(","));
        }
        this.visibilityEvaluator = new VisibilityEvaluator(authorizations);
    }

    @Override
    public Object run() {
        ScriptDocValues docValues = (ScriptDocValues) doc().get(securityExpressionField);

        if (docValues == null) {
            logger.warn("Document didn't contain '" + securityExpressionField + "' for security label check!");
            return false;
        }

        List values = docValues.getValues();
        if (values == null || values.isEmpty()) {
            logger.warn("Document contained no values in '" + securityExpressionField + "'!");
            return false;
        }

        String visibilityExpression = values.get(0).toString();

        Boolean result = (Boolean) cache.get(visibilityExpression);
        if (result != null) {
            return result;
        }

        try {
            result = visibilityEvaluator.evaluate(new ColumnVisibility(visibilityExpression));
            cache.put(visibilityExpression, result);
            return result;
        } catch (VisibilityParseException e) {
            logger.error("Document contained unparseable '" + securityExpressionField + "' <" + visibilityExpression + ">!");
            return false;
        }
    }
}
