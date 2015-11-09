package it.infn.security.saml.datasource.hibernate;

import org.parboiled.trees.ImmutableBinaryTreeNode;

public class QueryNode
    extends ImmutableBinaryTreeNode<QueryNode> {

    public static final int ATTREXPR = 0;

    public static final int LOGEXPR = 1;

    public static final int GRPEXPR = 2;

    public static final int VALEXPR = 3;

    private int type;

    private String attribute = null;

    private String operator;

    private String expr;

    public QueryNode(String attribute, String operator, String value) {
        super(null, null);

        this.type = ATTREXPR;
        if ("eq".equalsIgnoreCase(operator)) {

            expr = attribute + " = " + value;

        } else if ("ne".equalsIgnoreCase(operator)) {

            expr = attribute + " != " + value;

        } else if ("gt".equalsIgnoreCase(operator)) {

            expr = attribute + " > " + value;

        } else if ("ge".equalsIgnoreCase(operator)) {

            expr = attribute + " >= " + value;

        } else if ("lt".equalsIgnoreCase(operator)) {

            expr = attribute + " < " + value;

        } else if ("le".equalsIgnoreCase(operator)) {

            expr = attribute + " <= " + value;

        } else if ("co".equalsIgnoreCase(operator)) {

            value = value.substring(1, value.length() - 1);
            expr = attribute + " like \"%" + value + "%\"";

        } else if ("sw".equalsIgnoreCase(operator)) {

            value = value.substring(1);
            expr = attribute + " like \"%" + value;

        } else if ("ew".equalsIgnoreCase(operator)) {

            value = value.substring(0, value.length() - 1);
            expr = attribute + " like " + value + "%\"";

        } else if ("pr".equalsIgnoreCase(operator)) {

            expr = attribute + " != null ";
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

    protected String toString(String parentAttr) {

        if (type == ATTREXPR) {
            return parentAttr + "." + expr;
        }

        if (type == LOGEXPR) {
            return left().toString(parentAttr) + " " + operator + " " + right().toString(parentAttr);
        }

        if (type == GRPEXPR) {
            return operator + " ( " + left().toString(parentAttr) + " ) ";
        }

        return "";

    }

    public String toString() {
        if (type == ATTREXPR) {
            return expr;
        }

        if (type == LOGEXPR) {
            return left().toString() + " " + operator + " " + right().toString();
        }

        if (type == GRPEXPR) {
            return operator + " ( " + left().toString() + " ) ";
        }

        if (type == VALEXPR) {
            return left().toString(attribute);
        }

        return "";
    }

}
