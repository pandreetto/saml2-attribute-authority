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
                throw new DataSourceException("Detected cycle in the resource graph");
            }
            currSet.remove(accSet);
            accSet.addAll(idList);
        }
    }

    public void removeMembersFromGroup(GroupEntity grpEnt) {

        StringBuffer queryStr = new StringBuffer("SELECT qRes FROM ResourceEntity as qRes");
        queryStr.append(" INNER JOIN qRes.groups as rGroup WHERE rGroup.id=?");

        Query query = session.createQuery(queryStr.toString()).setString(0, grpEnt.getId());
        @SuppressWarnings("unchecked")
        List<ResourceEntity> members = query.list();

        for (ResourceEntity resEnt : members) {
            resEnt.getGroups().remove(grpEnt);
        }

    }

    public void addMembersToGroup(GroupEntity grpEnt, List<String> memberIds) {

        if (memberIds == null || memberIds.size() == 0)
            return;

        StringBuffer queryStr = new StringBuffer("FROM ResourceEntity as qRes");
        queryStr.append(" WHERE qRes.id in (:memberids)");

        Query query = session.createQuery(queryStr.toString());
        @SuppressWarnings("unchecked")
        List<ResourceEntity> mResList = query.setParameterList("memberids", memberIds).list();

        for (ResourceEntity tmpEnt : mResList) {
            tmpEnt.getGroups().add(grpEnt);
            logger.fine("Inserted member " + grpEnt.getId() + " into " + tmpEnt.getId());
            session.flush();
        }

    }

    public void updateMembersForGroup(GroupEntity grpEnt, List<String> memberIds) {

        if (memberIds == null || memberIds.size() == 0)
            return;

        StringBuffer queryStr = new StringBuffer("SELECT qRes FROM ResourceEntity as qRes");
        queryStr.append(" INNER JOIN qRes.groups as rGroup WHERE rGroup.id=:groupid");
        queryStr.append(" AND qRes.id not in (:memberids)");

        Query query = session.createQuery(queryStr.toString());
        query.setString("groupid", grpEnt.getId());
        query.setParameterList("memberids", memberIds);
        @SuppressWarnings("unchecked")
        List<ResourceEntity> oldMembers = query.list();

        for (ResourceEntity resEnt : oldMembers) {
            resEnt.getGroups().remove(grpEnt);
            logger.info("Removed member " + grpEnt.getId() + " from " + resEnt.getId());
        }

        StringBuffer query2Str = new StringBuffer("SELECT qRes FROM ResourceEntity as qRes");
        query2Str.append(" INNER JOIN qRes.groups as rGroup");
        query2Str.append(" WHERE qRes.id in (:memberids)");
        query2Str.append(" AND rGroup.id != :groupid");

        Query query2 = session.createQuery(query2Str.toString());
        query2.setString("groupid", grpEnt.getId());
        query2.setParameterList("memberids", memberIds);
        @SuppressWarnings("unchecked")
        List<ResourceEntity> newMembers = query2.list();

        for (ResourceEntity tmpEnt : newMembers) {
            tmpEnt.getGroups().add(grpEnt);
            logger.info("Inserted member " + grpEnt.getId() + " into " + tmpEnt.getId());
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