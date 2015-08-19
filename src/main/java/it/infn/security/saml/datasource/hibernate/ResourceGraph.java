package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.jpa.GroupEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity.ResourceType;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Logger;

import org.hibernate.Query;
import org.hibernate.Session;

public class ResourceGraph {

    private static final Logger logger = Logger.getLogger(ResourceGraph.class.getName());

    private Session session;

    public ResourceGraph(Session session) {
        this.session = session;
    }

    public HashSet<String> getDirectGroupIds(String resId) {

        StringBuffer queryStr = new StringBuffer("SELECT rGroups.id");
        queryStr.append(" FROM ResourceEntity as resource INNER JOIN resource.groups as rGroups");
        queryStr.append(" WHERE resource.id=?");

        Query query = session.createQuery(queryStr.toString());
        @SuppressWarnings("unchecked")
        List<String> idList = query.setString(0, resId).list();
        return new HashSet<String>(idList);
    }

    public HashSet<String> getIndirectGroupIds(HashSet<String> resIds) {
        HashSet<String> result = new HashSet<String>();
        HashSet<String> currSet = resIds;
        while (currSet.size() > 0) {

            StringBuffer queryStr = new StringBuffer("SELECT rGroups.id");
            queryStr.append(" FROM ResourceEntity as resource INNER JOIN resource.groups as rGroups");
            queryStr.append(" WHERE resource.id IN (:resourceIds)");

            Query query = session.createQuery(queryStr.toString());
            @SuppressWarnings("unchecked")
            List<String> idList = query.setParameterList("resourceIds", currSet).list();
            currSet = new HashSet<String>(idList);
            currSet.remove(result);
            result.addAll(idList);
        }

        return result;
    }

    public HashSet<String> getAllGroupIds(String resId) {
        HashSet<String> directGroupIds = getDirectGroupIds(resId);
        HashSet<String> result = getIndirectGroupIds(directGroupIds);
        result.addAll(directGroupIds);
        return result;
    }

    public void checkForCycle(String grpId)
        throws DataSourceException {

        HashSet<String> accSet = new HashSet<String>();
        accSet.add(grpId);
        HashSet<String> currSet = accSet;

        while (currSet.size() > 0) {

            StringBuffer queryStr = new StringBuffer("SELECT rGroups.id");
            queryStr.append(" FROM ResourceEntity as resource INNER JOIN resource.groups as rGroups");
            queryStr.append(" WHERE resource.id IN (:resourceIds)");

            Query query = session.createQuery(queryStr.toString());
            @SuppressWarnings("unchecked")
            List<String> idList = query.setParameterList("resourceIds", currSet).list();
            currSet = new HashSet<String>(idList);
            if (currSet.contains(grpId)) {
                throw new DataSourceException("Detected cycle in the groups graph");
            }
            currSet.remove(accSet);
            accSet.addAll(idList);
        }
    }

    public void removeGroupsForEntity(GroupEntity grpEnt) {
        /*
         * TODO lots of queries, missing index on source
         */
        StringBuffer queryStr = new StringBuffer("SELECT qRes FROM ResourceEntity as qRes");
        queryStr.append(" INNER JOIN qRes.groups as rGroup WHERE rGroup.id=?");

        Query query = session.createQuery(queryStr.toString()).setString(0, grpEnt.getId());
        @SuppressWarnings("unchecked")
        List<ResourceEntity> members = query.list();

        for (ResourceEntity resEnt : members) {
            resEnt.getGroups().remove(grpEnt);
        }

    }

    public void removeMembers(GroupEntity grpEnt, List<String> memberIds) {

        StringBuffer queryStr = new StringBuffer("FROM ResourceEntity as qRes");
        queryStr.append(" WHERE qRes.id in (:memberIds)");

        Query query = session.createQuery(queryStr.toString());
        @SuppressWarnings("unchecked")
        List<ResourceEntity> members = query.setParameterList("memberIds", memberIds).list();

        for (ResourceEntity resEnt : members) {
            resEnt.getGroups().remove(grpEnt);
            logger.fine("Removed member " + grpEnt.getId() + " from " + resEnt.getId());
        }

    }

    public void addMembers(GroupEntity grpEnt, List<String> memberIds) {

        StringBuffer queryStr = new StringBuffer("FROM ResourceEntity as qRes");
        queryStr.append(" WHERE qRes.id in (:memberIds)");

        Query query = session.createQuery(queryStr.toString());
        @SuppressWarnings("unchecked")
        List<ResourceEntity> mResList = query.setParameterList("memberIds", memberIds).list();

        /*
         * TODO improve query
         */
        for (ResourceEntity tmpEnt : mResList) {
            tmpEnt.getGroups().add(grpEnt);
            logger.fine("Inserted member " + grpEnt.getId() + " into " + tmpEnt.getId());
            session.flush();
        }

    }

    public List<MemberItem> getMembersForGroup(GroupEntity grpEnt) {

        List<MemberItem> result = new ArrayList<MemberItem>();

        StringBuffer queryStr = new StringBuffer("SELECT resource.id, resource.type");
        queryStr.append(" FROM ResourceEntity as resource INNER JOIN resource.groups as rGroups");
        queryStr.append(" WHERE rGroups.id=?");
        Query query = session.createQuery(queryStr.toString());
        @SuppressWarnings("unchecked")
        List<Object[]> directMembers = (List<Object[]>) query.setString(0, grpEnt.getId()).list();
        for (Object[] tmpObj : directMembers) {
            result.add(new MemberItem(tmpObj[0].toString(), (ResourceEntity.ResourceType) tmpObj[1]));
        }
        return result;

    }

    public class MemberItem {

        private String id;

        private ResourceEntity.ResourceType type;

        public MemberItem(String id, ResourceEntity.ResourceType type) {
            this.id = id;
            this.type = type;
        }

        public String getId() {
            return id;
        }

        public boolean isaUser() {
            return type == ResourceType.USER;
        }
    }
}