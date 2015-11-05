package it.infn.security.saml.datasource.hibernate;

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

    private String value;

    public QueryNode(String attribute, String operator, String value) {
        super(null, null);

        this.type = ATTREXPR;
        this.attribute = attribute;
        this.operator = operator;
        this.value = value;
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

    public String toString() {
        if (type == ATTREXPR) {
            return "<AE>" + attribute + ":" + operator + ":" + value + "</AE>";
        }

        if (type == LOGEXPR) {
            return "<LE>" + left().toString() + ":" + operator + ":" + right().toString() + "</LE>";
        }

        if (type == GRPEXPR) {
            return "<GE>" + ":" + operator + ":" + left().toString() + "</GE>";
        }

        if (type == VALEXPR) {
            return "<VE>" + attribute + ":" + left().toString() + "</VE>";
        }

        return "";
    }

    public int getType() {
        return 0;
    }

}
