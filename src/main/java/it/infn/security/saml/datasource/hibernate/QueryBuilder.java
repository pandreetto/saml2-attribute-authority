package it.infn.security.saml.datasource.hibernate;

import java.util.HashMap;

import org.hibernate.Query;
import org.hibernate.Session;

import it.infn.security.scim.protocol.SearchFilterNode;
import it.infn.security.scim.protocol.SearchFilterParser;

public class QueryBuilder {

    private static final String LABEL_FORMAT = "arg%05d";

    private static final String USER_ENT = "qUser";

    private static final String GROUP_ENT = "qGroup";

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

            String label = String.format(LABEL_FORMAT, params.size());
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

    private static Query[] buildSearch(boolean isUser, Session session, String filter, String sortBy,
            String sortOrder) {

        StringBuilder queryStr = new StringBuilder();
        HashMap<String, Object> params = new HashMap<String, Object>();
        StringBuffer output = new StringBuffer();

        if (isUser)
            queryStr.append("FROM UserEntity as ").append(USER_ENT);
        else
            queryStr.append("FROM GroupEntity as ").append(GROUP_ENT);

        if (filter != null && filter.length() > 0) {

            SearchFilterNode rootNode = SearchFilterParser.parse(filter);
            if (rootNode != null) {

                process(rootNode, output, params, null);

            }

        }

        String countQuery = "SELECT COUNT(*) " + queryStr.toString();

        if (sortBy != null) {
            sortBy = HibernateUtils.convertSortedParam(sortBy, true);
            queryStr.append(" ORDER BY ").append(sortBy);
            if (sortOrder != null && sortOrder.equalsIgnoreCase("descending")) {
                queryStr.append(" DESC");
            } else {
                queryStr.append(" ASC");
            }
        }

        Query query1 = session.createQuery(queryStr.toString());
        for (HashMap.Entry<String, Object> pItem : params.entrySet()) {
            query1.setParameter(pItem.getKey(), pItem.getValue());
        }

        Query query2 = session.createQuery(countQuery);
        return new Query[] { query1, query2 };
    }

    public static Query[] buildSearchUsers(Session session, String filter, String sortBy, String sortOrder) {
        return buildSearch(true, session, filter, sortBy, sortOrder);
    }

    public static Query[] buildSearchGroups(Session session, String filter, String sortBy, String sortOrder) {
        return buildSearch(false, session, filter, sortBy, sortOrder);
    }

}
