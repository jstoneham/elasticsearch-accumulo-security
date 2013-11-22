elasticsearch-accumulo-security
===============================

Created by @cgross.

Use the Accumulo ColumnVisibility security model to control access to your ElasticSearch documents.

For reference on the Accumulo security model: http://accumulo.apache.org/1.4/user_manual/Security.html

- Build the standalone JAR and deploy to your ElasticSearch nodes under elasticsearch-xxx/lib.
- Add to config/elasticsearch.yml:

```
script.native:
  visibility.type: org.elasticsearch.security.AccumuloSecurityScriptFactory
```

- Add a field "securityExpression" to your documents, which contains the string form of an Accumulo ColumnVisibility. Example: new String(columnVisibility.getExpression()), like "ABC&DEF&(GHI|JKL)". NOTE: passing filter parameter "expressionField" allows you to customize the name of this field.
- Ensure that your field is not_analyzed otherwise ElasticSearch will attempt to analyze security expressions like A&B&(C|E|F)
- When querying, add a filter to invoke the script like so:

```
Authorizations auths = new Authorizations("ABC", "DEF", "GHI");
filters.add(FilterBuilders.scriptFilter("visibility").lang("native").
    addParam("auths", auths.serialize()).addParam("expressionField", "myCustomSecurityFieldName"));
```


Artifacts currently not available in any public Maven repo.
To release:

mvn release:prepare
mvn release:perform -Darguments="-DaltDeploymentRepository=REPOIDHERE::default::REPOURLHERE"
(example: mvn release:perform -Darguments="-DaltDeploymentRepository=mycompany::default::http://192.168.1.1:8080/nexus/content/repositories/releases")
