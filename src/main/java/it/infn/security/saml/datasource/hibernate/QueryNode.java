package it.infn.security.saml.datasource.hibernate;

import java.util.HashMap;

import org.parboiled.trees.ImmutableBinaryTreeNode;

public class QueryNode
    extends ImmutableBinaryTreeNode<QueryNode> {

    public static final int ATTREXPR = 0;

    public static final int LOGEXPR = 1;

    public static final int GRPEXPR = 2;

    public static final int VALEXPR = 3;

    private int type;

    private String attribute;

    private String operator;

    private String label;

    private Object value;

    public QueryNode(String attribute, String operator, String value) {
        super(null, null);

        this.type = ATTREXPR;
        this.attribute = attribute;

        if (value == null || value.length() == 0) {

            label = null;

        } else {

            label = String.valueOf(System.currentTimeMillis());

            if (value.startsWith("\"")) {
                this.value = value.substring(1, value.length() - 1);
            } else if ("true".equalsIgnoreCase(value)) {
                this.value = Boolean.TRUE;
            } else if ("false".equalsIgnoreCase(value)) {
                this.value = Boolean.FALSE;
            } else if (value.length() > 0) {
                this.value = Long.parseLong(value);
            }
            /*
             * TODO missing null
             */
        }

        if ("eq".equalsIgnoreCase(operator)) {

            this.operator = "=";

        } else if ("ne".equalsIgnoreCase(operator)) {

            this.operator = "!=";

        } else if ("gt".equalsIgnoreCase(operator)) {

            this.operator = ">";

        } else if ("ge".equalsIgnoreCase(operator)) {

            this.operator = ">=";

        } else if ("lt".equalsIgnoreCase(operator)) {

            this.operator = "<";

        } else if ("le".equalsIgnoreCase(operator)) {

            this.operator = "<=";

        } else if ("co".equalsIgnoreCase(operator)) {

            this.operator = "like '%-%'";

        } else if ("sw".equalsIgnoreCase(operator)) {

            this.operator = "like '-%'";

        } else if ("ew".equalsIgnoreCase(operator)) {

            this.operator = "like '%-'";

        } else if ("pr".equalsIgnoreCase(operator)) {

            this.operator = "is not null";

        }

    }

    public QueryNode(QueryNode left, String operator, QueryNode right) {
        super(left, right);

        this.type = LOGEXPR;
        this.operator = operator;

    }

    public QueryNode(QueryNode node, boolean notExpr) {
        super(node, null);

        this.type = GRPEXPR;
        this.operator = notExpr ? "not" : "";

    }

    public QueryNode(String attribute, QueryNode left) {
        super(left, null);

        this.type = VALEXPR;
        this.attribute = attribute;

    }

    private String operAndValue() {
        if (label != null) {
            if (operator.startsWith("like")) {
                return operator.replace("-", ":" + label);
            }
            return operator + " :" + label;
        }
        return operator;
    }

    protected String getFormatString(String parentAttr) {

        if (type == ATTREXPR) {
            return parentAttr + "." + attribute + " " + operAndValue();
        }

        if (type == LOGEXPR) {
            return left().getFormatString(parentAttr) + " " + operator + " " + right().getFormatString(parentAttr);
        }

        if (type == GRPEXPR) {
            return operator + " ( " + left().getFormatString(parentAttr) + " ) ";
        }

        return "";

    }

    public String getFormatString() {
        if (type == ATTREXPR) {
            return attribute + " " + operAndValue();
        }

        if (type == LOGEXPR) {
            return left().getFormatString() + " " + operator + " " + right().getFormatString();
        }

        if (type == GRPEXPR) {
            return operator + " ( " + left().getFormatString() + " ) ";
        }

        if (type == VALEXPR) {
            return left().getFormatString(attribute);
        }

        return "";
    }

    public void fillinParameters(HashMap<String, Object> parameters) {

        if (type == ATTREXPR && label != null) {
            parameters.put(label, value);
        } else if (type == LOGEXPR) {
            left().fillinParameters(parameters);
            right().fillinParameters(parameters);
        } else if (type == GRPEXPR || type == VALEXPR) {
            left().fillinParameters(parameters);
        }

    }

}
