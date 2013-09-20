package org.elasticsearch.security;

import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.accumulo.core.security.VisibilityEvaluator;
import org.apache.accumulo.core.security.VisibilityParseException;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.index.fielddata.ScriptDocValues;
import org.elasticsearch.script.AbstractSearchScript;

import java.util.List;
import java.util.Map;

public class AccumuloVisibilityFilter extends AbstractSearchScript {

    private final ESLogger logger;
    private final Map<String, Object> params;

    public AccumuloVisibilityFilter(Map<String, Object> params, ESLogger logger) {
        this.logger = logger;
        this.params = params;
    }

    @Override
    public Object run() {
        String securityExpressionField = "securityExpression";
        if (params.get("expressionField") != null) {
            securityExpressionField = params.get("expressionField").toString();
        }

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

        String auths = params.get("auths").toString();
        Authorizations authorizations = new Authorizations(auths.split(","));
        String visibilityExpression = values.get(0).toString();

        try {
            return new VisibilityEvaluator(authorizations).evaluate(new ColumnVisibility(visibilityExpression));
        } catch (VisibilityParseException e) {
            logger.error("Document contained unparseable '" + securityExpressionField + "' <" + visibilityExpression + ">!");
            return false;
        }
    }
}
