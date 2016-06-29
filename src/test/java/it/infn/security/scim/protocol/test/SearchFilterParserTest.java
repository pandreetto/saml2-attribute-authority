package it.infn.security.scim.protocol.test;

import java.util.HashMap;

import it.infn.security.scim.protocol.SearchFilterNode;
import it.infn.security.scim.protocol.SearchFilterParser;

import org.junit.Assert;
import org.junit.Test;

public class SearchFilterParserTest {

    private static final String labelFmt = "arg%05d";

    private void process(SearchFilterNode node, StringBuffer output, HashMap<String, Object> params, String parentAttr) {

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

    @Test
    public void translateQuery() {

        String inStr = "role co \"admin\" or priv.capability pr or not (category[level lt 10 and time.elaps eq 5])";
        String outStr = "role like %:arg00000%  or priv.capability is not null   or not (category.level < :arg00001  and category.time.elaps == :arg00002  )";

        try {
            SearchFilterNode rootNode = SearchFilterParser.parse(inStr);
            if (rootNode != null) {
                HashMap<String, Object> params = new HashMap<String, Object>();
                StringBuffer output = new StringBuffer();

                process(rootNode, output, params, null);

                Assert.assertEquals("Query", outStr, output.toString().trim());
                Assert.assertEquals("Argument #0", "admin", params.get("arg00000"));
                Assert.assertEquals("Argument #1", "10", params.get("arg00001").toString());
                Assert.assertEquals("Argument #2", "5", params.get("arg00002").toString());

            } else {
                Assert.fail("Error parsing: '" + inStr + "'");
            }

        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail(ex.getMessage());
        }

    }
}