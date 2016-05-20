package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupResource;
import it.infn.security.saml.datasource.GroupSearchResult;
import it.infn.security.saml.datasource.UserResource;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.datasource.jpa.ExternalIdEntity;
import it.infn.security.saml.datasource.jpa.GroupEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity.ResourceStatus;
import it.infn.security.saml.datasource.jpa.ResourceEntity.ResourceType;
import it.infn.security.saml.datasource.jpa.UserEntity;
import it.infn.security.scim.core.SCIMGroup;
import it.infn.security.scim.core.SCIMUser;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import org.hibernate.Query;
import org.hibernate.Session;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.AbstractSCIMObject;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.User;

public abstract class HibernateDataSource
    extends HibernateBaseDataSource {

    private static final Logger logger = Logger.getLogger(HibernateDataSource.class.getName());

    public HibernateDataSource() {
    }

    public UserResource getUser(String userId)
        throws DataSourceException {

        UserResource result = null;
        Session session = sessionFactory.getCurrentSession();
        boolean nocommit = true;

        try {

            session.beginTransaction();
            UserEntity usrEnt = (UserEntity) session.get(UserEntity.class, userId);
            if (usrEnt == null) {
                throw new DataSourceException("Entity not found " + userId);
            }

            result = userFromEntity(session, usrEnt);
            session.getTransaction().commit();
            nocommit = false;

        } catch (CharonException chEx) {

            throw new DataSourceException(chEx.getMessage());

        } finally {

            if (nocommit)
                session.getTransaction().rollback();

        }
        return result;
    }

    public List<UserResource> listUsers()
        throws DataSourceException {
        return listUsers(null, null, null, -1, -1).getUserList();
    }

    public List<UserResource> listUsersByFilter(String filter, String operation, String value)
        throws DataSourceException {

        return listUsers(filter + operation + value, null, null, -1, -1).getUserList();

    }

    public List<UserResource> listUsersBySort(String sortBy, String sortOrder)
        throws DataSourceException {
        return listUsers(null, sortBy, sortOrder, -1, -1).getUserList();
    }

    public List<UserResource> listUsersWithPagination(int startIndex, int count)
        throws DataSourceException {
        return listUsers(null, null, null, startIndex, count).getUserList();
    }

    public UserSearchResult listUsers(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws DataSourceException {

        count = HibernateUtils.checkQueryRange(count, true);

        UserSearchResult result = new UserSearchResult(count);

        Session session = sessionFactory.getCurrentSession();
        boolean nocommit = true;

        try {

            session.beginTransaction();

            StringBuffer queryStr = new StringBuffer("FROM UserEntity as qUser");

            if (sortBy != null) {
                sortBy = HibernateUtils.convertSortedParam(sortBy, true);
                queryStr.append(" ORDER BY ").append(sortBy);
                if (sortOrder != null && sortOrder.equalsIgnoreCase("descending")) {
                    queryStr.append(" DESC");
                } else {
                    queryStr.append(" ASC");
                }
            }

            Query query = session.createQuery(queryStr.toString());
            if (startIndex >= 0)
                query.setFirstResult(startIndex);
            if (count > 0)
                query.setMaxResults(count);

            @SuppressWarnings("unchecked")
            List<UserEntity> usersFound = query.list();

            for (UserEntity usrEnt : usersFound) {
                result.add(userFromEntity(session, usrEnt));
            }

            Query query2 = session.createQuery("SELECT COUNT(*) FROM UserEntity as qUser");
            @SuppressWarnings("unchecked")
            Iterator<Long> totalUser = query2.list().iterator();
            if (totalUser.hasNext()) {
                result.setTotalResults(totalUser.next().intValue());
            }

            session.getTransaction().commit();
            nocommit = false;

        } catch (CharonException chEx) {

            throw new DataSourceException(chEx.getMessage());

        } finally {

            if (nocommit)
                session.getTransaction().rollback();

        }

        return result;
    }

    public UserResource updateUser(UserResource userRes)
        throws DataSourceException {

        Session session = sessionFactory.getCurrentSession();
        boolean nocommit = true;

        try {

            session.beginTransaction();

            User user = (User) userRes;

            UserEntity eUser = (UserEntity) session.get(UserEntity.class, user.getId());
            eUser.setModifyDate(user.getLastModified());
            eUser.setVersion(HibernateUtils.generateNewVersion(eUser.getVersion()));
            eUser.setUserName(user.getUserName());

            cleanSCIMAttributes(session, eUser);
            HibernateUtils.copyAttributesInEntity(user, eUser);

            cleanUserExtAttributes(session, eUser);
            fillinUserExtAttributes(session, user, eUser);

            session.save(eUser);
            logger.info("Updated user " + user.getUserName() + " with id " + user.getId());

            updateExternalIds(session, eUser, user.getExternalId());

            session.getTransaction().commit();
            nocommit = false;

            return userRes;

        } catch (CharonException chEx) {

            throw new DataSourceException(chEx.getMessage());

        } catch (NotFoundException nfEx) {

            throw new DataSourceException(nfEx.getMessage());

        } finally {

            if (nocommit)
                session.getTransaction().rollback();

        }
    }

    public void deleteUser(String userId)
        throws DataSourceException {

        Session session = sessionFactory.getCurrentSession();
        boolean nocommit = true;

        try {

            session.beginTransaction();

            UserEntity usrEnt = (UserEntity) session.get(UserEntity.class, userId);
            if (usrEnt == null) {
                logger.info("Entity not found " + userId);
                throw new NotFoundException();
            }

            session.delete(usrEnt);

            session.getTransaction().commit();
            nocommit = false;

        } catch (NotFoundException nfEx) {

            throw new DataSourceException(nfEx.getMessage());

        } finally {

            if (nocommit)
                session.getTransaction().rollback();

        }
    }

    public UserResource createUser(UserResource user)
        throws DataSourceException {
        return createUser(user, false);
    }

    public UserResource createUser(UserResource userRes, boolean isBulkUserAdd)
        throws DataSourceException {

        Session session = sessionFactory.getCurrentSession();
        boolean nocommit = true;

        try {

            session.beginTransaction();

            UserEntity eUser = new UserEntity();
            /*
             * The uid is auto-generated by the SCIM parser
             * ServerSideValidator#validateCreatedSCIMObject(AbstractSCIMObject,
             * SCIMResourceSchema)
             */

            User user = (User) userRes;

            eUser.setId(user.getId());
            eUser.setType(ResourceType.USER);
            eUser.setStatus(ResourceStatus.ACTIVE);
            eUser.setCreateDate(user.getCreatedDate());
            eUser.setModifyDate(user.getLastModified());
            eUser.setVersion(HibernateUtils.generateNewVersion(null));
            eUser.setUserName(user.getUserName());

            HibernateUtils.copyAttributesInEntity(user, eUser);

            fillinUserExtAttributes(session, user, eUser);

            session.save(eUser);
            logger.info("Created user " + user.getUserName() + " with id " + user.getId());

            linkExternalIds(session, eUser, user.getExternalId());

            session.getTransaction().commit();
            nocommit = false;

            return userRes;

        } catch (CharonException chEx) {

            throw new DataSourceException(chEx.getMessage());

        } catch (NotFoundException nfEx) {

            throw new DataSourceException(nfEx.getMessage());

        } finally {

            if (nocommit)
                session.getTransaction().rollback();

        }
    }

    public GroupResource getGroup(String groupId)
        throws DataSourceException {

        GroupResource result = null;
        Session session = sessionFactory.getCurrentSession();
        boolean nocommit = true;

        try {

            session.beginTransaction();
            GroupEntity grpEnt = (GroupEntity) session.get(GroupEntity.class, groupId);
            if (grpEnt == null) {
                throw new DataSourceException("Entity not found " + groupId);
            }

            result = groupFromEntity(session, grpEnt);
            session.getTransaction().commit();
            nocommit = false;

        } catch (CharonException chEx) {

            throw new DataSourceException(chEx.getMessage());

        } finally {

            if (nocommit)
                session.getTransaction().rollback();

        }
        return result;
    }

    public List<GroupResource> listGroups()
        throws DataSourceException {
        return listGroups(null, null, null, -1, -1).getGroupList();
    }

    public List<GroupResource> listGroupsByFilter(String filter, String operation, String value)
        throws DataSourceException {
        return listGroups(filter + operation + value, null, null, -1, -1).getGroupList();
    }

    public List<GroupResource> listGroupsBySort(String sortBy, String sortOrder)
        throws DataSourceException {
        return listGroups(null, sortBy, sortOrder, -1, -1).getGroupList();
    }

    public List<GroupResource> listGroupsWithPagination(int startIndex, int count)
        throws DataSourceException {
        return listGroups(null, null, null, startIndex, count).getGroupList();
    }

    public GroupSearchResult listGroups(String filter, String sortBy, String sortOrder, int startIndex, int count)
        throws DataSourceException {

        count = HibernateUtils.checkQueryRange(count, false);

        GroupSearchResult result = new GroupSearchResult(count);

        Session session = sessionFactory.getCurrentSession();

        boolean nocommit = true;

        try {

            session.beginTransaction();

            StringBuffer queryStr = new StringBuffer("FROM GroupEntity as qGroup");

            if (sortBy != null) {
                sortBy = HibernateUtils.convertSortedParam(sortBy, false);
                queryStr.append(" ORDER BY ").append(sortBy);
                if (sortOrder != null && sortOrder.equalsIgnoreCase("descending")) {
                    queryStr.append(" DESC");
                } else {
                    queryStr.append(" ASC");
                }
            }

            Query query = session.createQuery(queryStr.toString());
            if (startIndex >= 0)
                query.setFirstResult(startIndex);
            if (count > 0)
                query.setMaxResults(count);

            @SuppressWarnings("unchecked")
            List<GroupEntity> groupsFound = query.list();

            for (GroupEntity grpEnt : groupsFound) {
                result.add(groupFromEntity(session, grpEnt));
            }

            Query query2 = session.createQuery("SELECT COUNT(*) FROM GroupEntity as qGroup");
            @SuppressWarnings("unchecked")
            Iterator<Long> totalGroup = query2.list().iterator();
            if (totalGroup.hasNext()) {
                result.setTotalResults(totalGroup.next().intValue());
            }

            session.getTransaction().commit();
            nocommit = false;

        } catch (CharonException chEx) {

            throw new DataSourceException(chEx.getMessage());

        } finally {

            if (nocommit)
                session.getTransaction().rollback();

        }

        return result;
    }

    public GroupResource createGroup(GroupResource groupRes)
        throws DataSourceException {
        Session session = sessionFactory.getCurrentSession();
        boolean nocommit = true;

        try {

            session.beginTransaction();

            GroupEntity grpEnt = new GroupEntity();
            /*
             * The gid is auto-generated by the SCIM parser
             * ServerSideValidator#validateCreatedSCIMObject(AbstractSCIMObject,
             * SCIMResourceSchema)
             */

            Group group = (Group) groupRes;

            grpEnt.setId(group.getId());
            grpEnt.setType(ResourceType.GROUP);
            grpEnt.setStatus(ResourceStatus.ACTIVE);
            grpEnt.setCreateDate(group.getCreatedDate());
            grpEnt.setModifyDate(group.getLastModified());
            grpEnt.setVersion(HibernateUtils.generateNewVersion(null));
            grpEnt.setDisplayName(group.getDisplayName());

            fillinGroupExtAttributes(session, group, grpEnt);

            session.save(grpEnt);
            logger.info("Created group " + grpEnt.getDisplayName() + " with id " + group.getId());

            linkExternalIds(session, grpEnt, group.getExternalId());

            ResourceGraph rGraph = new ResourceGraph(session);
            rGraph.addMembersToGroup(grpEnt, group.getMembers());

            session.getTransaction().commit();
            nocommit = false;

            return groupRes;

        } catch (CharonException chEx) {

            throw new DataSourceException(chEx.getMessage());

        } catch (NotFoundException nfEx) {

            throw new DataSourceException(nfEx.getMessage());

        } finally {

            if (nocommit)
                session.getTransaction().rollback();

        }

    }

    public GroupResource updateGroup(GroupResource oldGroup, GroupResource groupRes)
        throws DataSourceException {
        Session session = sessionFactory.getCurrentSession();
        boolean nocommit = true;

        try {

            session.beginTransaction();

            Group group = (Group) groupRes;

            GroupEntity eGroup = (GroupEntity) session.get(GroupEntity.class, group.getId());
            eGroup.setModifyDate(group.getLastModified());
            eGroup.setVersion(HibernateUtils.generateNewVersion(eGroup.getVersion()));
            eGroup.setDisplayName(group.getDisplayName());

            cleanGroupExtAttributes(session, eGroup);
            fillinGroupExtAttributes(session, group, eGroup);

            ResourceGraph rGraph = new ResourceGraph(session);
            // rGraph.updateMembersForGroup(eGroup, group.getMembers());
            rGraph.removeMembersFromGroup(eGroup);
            rGraph.addMembersToGroup(eGroup, group.getMembers());
            rGraph.checkForCycle(eGroup.getId());

            updateExternalIds(session, eGroup, group.getExternalId());

            session.save(eGroup);
            logger.info("Updated user " + group.getDisplayName() + " with id " + group.getId());

            session.getTransaction().commit();
            nocommit = false;

            return groupRes;

        } catch (CharonException chEx) {

            throw new DataSourceException(chEx.getMessage());

        } catch (NotFoundException nfEx) {

            throw new DataSourceException(nfEx.getMessage());

        } finally {

            if (nocommit)
                session.getTransaction().rollback();

        }
    }

    public GroupResource patchGroup(GroupResource oldGroup, GroupResource group)
        throws DataSourceException {
        return null;
    }

    public void deleteGroup(String groupId)
        throws DataSourceException {
        Session session = sessionFactory.getCurrentSession();
        boolean nocommit = true;

        try {

            session.beginTransaction();
            GroupEntity grpEnt = (GroupEntity) session.get(GroupEntity.class, groupId);
            if (grpEnt == null) {
                logger.info("Entity not found " + groupId);
                throw new NotFoundException();
            }

            ResourceGraph rGraph = new ResourceGraph(session);
            rGraph.removeMembersFromGroup(grpEnt);

            session.delete(grpEnt);
            session.getTransaction().commit();
            nocommit = false;

        } catch (NotFoundException nfEx) {

            throw new DataSourceException(nfEx.getMessage());

        } finally {

            if (nocommit)
                session.getTransaction().rollback();

        }
    }

    private void cleanSCIMAttributes(Session session, UserEntity eUser) {

        /*
         * TODO passwd attribute must be kept
         */
        StringBuffer queryStr = new StringBuffer("DELETE FROM UserAttributeEntity as usrAttr");
        queryStr.append(" WHERE usrAttr.user.id=:userid");
        Query query = session.createQuery(queryStr.toString());
        query.setString("userid", eUser.getId());
        int deletedItems = query.executeUpdate();
        logger.fine("Removed " + deletedItems + " user attributes for " + eUser.getId());

        StringBuffer query2Str = new StringBuffer("DELETE FROM UserAddressEntity as usrAddr");
        query2Str.append(" WHERE usrAddr.user.id=:userid");
        Query query2 = session.createQuery(query2Str.toString());
        query2.setString("userid", eUser.getId());
        deletedItems = query2.executeUpdate();
        logger.fine("Removed " + deletedItems + " user addresses for " + eUser.getId());

    }

    private String getExternalId(Session session, ResourceEntity resEnt)
        throws CharonException {

        if (this.getTenant() == null)
            return null;

        Set<Principal> principalSet = this.getTenant().getPrincipals(Principal.class);

        if (principalSet.size() > 0) {
            List<String> tenantNames = new ArrayList<String>(principalSet.size());
            for (Principal tmpp : principalSet) {
                tenantNames.add(tmpp.getName());
            }

            StringBuffer queryStr = new StringBuffer("SELECT qExtId FROM ResourceEntity as qRes");
            queryStr.append(" INNER JOIN qRes.externalIds as qExtId");
            queryStr.append(" WHERE qRes.id=:resourceid AND qExtId.tenant in (:tenantlist)");

            Query query = session.createQuery(queryStr.toString());
            query.setString("resourceid", resEnt.getId());
            query.setParameterList("tenantlist", tenantNames);

            @SuppressWarnings("unchecked")
            List<ExternalIdEntity> extIdList = query.list();

            if (extIdList.size() > 0) {
                return extIdList.get(0).getExtId();
            }

        }

        return null;

    }

    private void linkExternalIds(Session session, ResourceEntity resEntity, String extId)
        throws DataSourceException {

        if (this.getTenant() == null) {
            throw new DataSourceException("Datasource is not a proxy");
        }

        if (extId == null || extId.length() == 0) {
            return;
        }

        Set<Principal> principalSet = this.getTenant().getPrincipals(Principal.class);

        for (Principal tmpp : principalSet) {
            ExternalIdEntity tmpEnt = new ExternalIdEntity();
            tmpEnt.setExtId(extId);
            tmpEnt.setTenant(tmpp.getName());
            tmpEnt.setOwner(resEntity);

            session.save(tmpEnt);

            resEntity.getExternalIds().add(tmpEnt);
        }

    }

    private void updateExternalIds(Session session, ResourceEntity resEntity, String extId)
        throws DataSourceException {

        if (this.getTenant() == null) {
            throw new DataSourceException("Datasource is not a proxy");
        }

        Set<Principal> principalSet = this.getTenant().getPrincipals(Principal.class);
        List<String> tenantNames = new ArrayList<String>(principalSet.size());
        for (Principal tmpp : principalSet) {
            tenantNames.add(tmpp.getName());
        }

        if (extId == null || extId.length() == 0) {

            StringBuffer queryStr = new StringBuffer("DELETE FROM ExternalIdEntity as extId");
            queryStr.append(" WHERE extId.owner.id=:resourceid");
            queryStr.append(" AND extId.tenant in (:tenantlist)");
            Query query = session.createQuery(queryStr.toString());
            query.setString("resourceid", resEntity.getId());
            query.setParameterList("tenantlist", tenantNames);
            int deletedItems = query.executeUpdate();
            logger.fine("Removed " + deletedItems + " external id for " + resEntity.getId());

        } else {

            StringBuffer queryStr = new StringBuffer("UPDATE ExternalIdEntity as extIdEnt");
            queryStr.append(" SET extIdEnt.extId=:newid");
            queryStr.append(" WHERE extIdEnt.owner.id=:resourceid");
            queryStr.append(" AND extIdEnt.tenant in (:tenantlist)");
            Query query = session.createQuery(queryStr.toString());
            query.setString("newid", extId);
            query.setString("resourceid", resEntity.getId());
            query.setParameterList("tenantlist", tenantNames);
            int updatedItems = query.executeUpdate();

            if (updatedItems == 0) {
                linkExternalIds(session, resEntity, extId);
            } else {
                logger.fine("Updated " + updatedItems + " external id for " + resEntity.getId());
            }
        }
    }

    private UserResource userFromEntity(Session session, UserEntity usrEnt)
        throws CharonException, DataSourceException {
        /*
         * TODO remove uResult
         */
        UserResource uResult = new SCIMUser();
        User result = (User) uResult;
        result.setId(usrEnt.getId());
        result.setUserName(usrEnt.getUserName());
        result.setCreatedDate(usrEnt.getCreateDate());
        result.setLastModified(usrEnt.getModifyDate());
        result.setVersion(usrEnt.getVersion());

        ResourceGraph graph = new ResourceGraph(session);
        HashSet<String> dGroups = graph.getDirectGroupIds(usrEnt.getId());
        HashSet<String> iGroups = graph.getIndirectGroupIds(dGroups);

        result.setDirectGroups(new ArrayList<String>(dGroups));
        result.setIndirectGroups(new ArrayList<String>(iGroups));

        String externalId = getExternalId(session, usrEnt);
        if (externalId != null)
            result.setExternalId(externalId);

        HibernateUtils.copyAttributesInUser(usrEnt, result);

        return uResult;
    }

    private GroupResource groupFromEntity(Session session, GroupEntity grpEnt)
        throws CharonException {
        /*
         * TODO remove gResult
         */
        GroupResource gResult = new SCIMGroup();
        Group result = (Group) gResult;
        result.setId(grpEnt.getId());
        result.setDisplayName(grpEnt.getDisplayName());
        result.setCreatedDate(grpEnt.getCreateDate());
        result.setLastModified(grpEnt.getModifyDate());
        result.setVersion(grpEnt.getVersion());

        ResourceGraph rGraph = new ResourceGraph(session);
        for (ResourceGraph.MemberItem item : rGraph.getMembersForGroup(grpEnt)) {
            if (item.isaUser()) {
                result.setUserMember(item.getId());
            } else {
                result.setGroupMember(item.getId());
            }
        }

        String externalId = getExternalId(session, grpEnt);
        if (externalId != null)
            result.setExternalId(externalId);

        return gResult;
    }

    protected abstract void fillinUserExtAttributes(Session session, AbstractSCIMObject resource, UserEntity uEnt)
        throws CharonException, NotFoundException, DataSourceException;

    protected abstract void fillinGroupExtAttributes(Session session, AbstractSCIMObject resource, GroupEntity gEnt)
        throws CharonException, NotFoundException, DataSourceException;

    protected abstract void cleanUserExtAttributes(Session session, UserEntity uEnt)
        throws DataSourceException;

    protected abstract void cleanGroupExtAttributes(Session session, GroupEntity gEnt)
        throws DataSourceException;

}