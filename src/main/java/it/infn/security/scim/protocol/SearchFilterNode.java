package it.infn.security.scim.protocol;

import org.parboiled.trees.ImmutableBinaryTreeNode;

public class SearchFilterNode
    extends ImmutableBinaryTreeNode<SearchFilterNode> {

    public enum NodeType {
        ATTREXPR, LOGEXPR, GRPEXPR, VALEXPR
    };

    public static final int NO_OP = 0;

    public static final int OP_EQ = 1;

    public static final int OP_NE = 2;

    public static final int OP_GT = 3;

    public static final int OP_GE = 4;

    public static final int OP_LT = 5;

    public static final int OP_LE = 6;

    public static final int OP_CO = 7;

    public static final int OP_SW = 8;

    public static final int OP_EW = 9;

    public static final int OP_PR = 10;

    public static final int OP_NOT = 11;

    public static final int OP_AND = 12;

    public static final int OP_OR = 13;

    protected NodeType type;

    protected String attribute;

    protected int operator;

    protected Object value;

    public SearchFilterNode(String attribute, String operator, String value) {
        super(null, null);

        this.type = NodeType.ATTREXPR;
        this.attribute = attribute;
        this.operator = convertOp(operator);

        if (value != null && value.length() > 0) {
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
    }

    public SearchFilterNode(SearchFilterNode left, String operator, SearchFilterNode right) {
        super(left, right);

        this.type = NodeType.LOGEXPR;
        this.operator = convertOp(operator);

    }

    public SearchFilterNode(SearchFilterNode node, boolean notExpr) {
        super(node, null);

        this.type = NodeType.GRPEXPR;
        this.operator = notExpr ? OP_NOT : NO_OP;

    }

    public SearchFilterNode(String attribute, SearchFilterNode node) {
        super(node, null);

        this.type = NodeType.VALEXPR;
        this.attribute = attribute;

    }

    public boolean isAttributeExpr() {
        return type == NodeType.ATTREXPR;
    }

    public boolean isLogicalExpr() {
        return type == NodeType.LOGEXPR;
    }

    public boolean isGroupExpr() {
        return type == NodeType.GRPEXPR;
    }

    public boolean isValueExpr() {
        return type == NodeType.VALEXPR;
    }

    public int getOperator() {
        return operator;
    }

    public String getAttribute() {
        return attribute;
    }

    public Object getValue() {
        return value;
    }

    public String getValueAsString() {
        return value.toString();
    }

    public boolean getValueAsBoolean() {
        return ((Boolean) value).booleanValue();
    }

    public long getValueAsLong() {
        return ((Long) value).longValue();
    }

    private int convertOp(String operator) {

        if ("eq".equalsIgnoreCase(operator)) {
            return OP_EQ;
        }

        if ("ne".equalsIgnoreCase(operator)) {
            return OP_NE;
        }

        if ("gt".equalsIgnoreCase(operator)) {
            return OP_GT;
        }

        if ("ge".equalsIgnoreCase(operator)) {
            return OP_GE;
        }

        if ("lt".equalsIgnoreCase(operator)) {
            return OP_LT;
        }

        if ("le".equalsIgnoreCase(operator)) {
            return OP_LE;
        }

        if ("co".equalsIgnoreCase(operator)) {
            return OP_CO;
        }

        if ("sw".equalsIgnoreCase(operator)) {
            return OP_SW;
        }

        if ("ew".equalsIgnoreCase(operator)) {
            return OP_EW;
        }

        if ("pr".equalsIgnoreCase(operator)) {
            return OP_PR;
        }

        if ("and".equalsIgnoreCase(operator)) {
            return OP_AND;
        }

        if ("or".equalsIgnoreCase(operator)) {
            return OP_OR;
        }

        return NO_OP;

    }
}