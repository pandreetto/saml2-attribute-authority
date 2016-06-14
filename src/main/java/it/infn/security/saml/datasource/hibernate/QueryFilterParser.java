package it.infn.security.saml.datasource.hibernate;

import it.infn.security.scim.protocol.SearchFilterNode;
import it.infn.security.scim.protocol.SearchFilterParser;

import java.util.HashMap;

public class QueryFilterParser {

    private static final String labelFmt = "arg%05d";

    private static void process(SearchFilterNode node, StringBuffer output, HashMap<String, Object> params,
            String parentAttr) {

        if (node.isAttributeExpr()) {

            if (parentAttr != null)
                output.append(parentAttr).append(".");
            output.append(node.getAttribute()).append(" ");

            if (node.getOperator() == SearchFilterNode.OP_PR) {
                output.append("is not null ");
                return;
            }

            String label = String.format(labelFmt, params.size());
            params.put(label, node.getValue());

            switch (node.getOperator()) {
            case SearchFilterNode.OP_EQ:
                output.append("== :").append(label);
                break;
            case SearchFilterNode.OP_NE:
                output.append("!= :").append(label);
                break;
            case SearchFilterNode.OP_GT:
                output.append("> :").append(label);
                break;
            case SearchFilterNode.OP_GE:
                output.append(">= :").append(label);
                break;
            case SearchFilterNode.OP_LT:
                output.append("< :").append(label);
                break;
            case SearchFilterNode.OP_LE:
                output.append("<= :").append(label);
                break;
            case SearchFilterNode.OP_CO:
                output.append("like %:").append(label).append("%");
                break;
            case SearchFilterNode.OP_SW:
                output.append("like %:").append(label);
                break;
            case SearchFilterNode.OP_EW:
                output.append("like :").append(label).append("%");
                break;
            }

            output.append(" ");

        } else if (node.isLogicalExpr()) {

            process(node.left(), output, params, parentAttr);
            output.append(" ");

            switch (node.getOperator()) {
            case SearchFilterNode.OP_AND:
                output.append("and");
                break;
            case SearchFilterNode.OP_OR:
                output.append("or");
                break;
            default:
                output.append(node.getOperator());
            }

            output.append(" ");
            process(node.right(), output, params, parentAttr);
            output.append(" ");

        } else if (node.isGroupExpr()) {

            if (node.getOperator() == SearchFilterNode.OP_NOT) {
                output.append("not");
            }
            output.append(" (");
            process(node.left(), output, params, parentAttr);
            output.append(") ");

        } else if (node.isValueExpr()) {

            process(node.left(), output, params, node.getAttribute());

        }
    }

    public static void main(String args[]) {

        try {

            SearchFilterNode rootNode = SearchFilterParser.parse(args[0]);
            if (rootNode != null) {
                HashMap<String, Object> params = new HashMap<String, Object>();
                StringBuffer output = new StringBuffer();

                process(rootNode, output, params, null);

                System.out.println(output.toString());
                for (String key : params.keySet()) {
                    System.out.println(key + " = " + params.get(key).toString());
                }
            } else {
                System.out.println("Error parsing " + args[0]);
            }

        } catch (Throwable th) {
            th.printStackTrace();
        }

    }

}
