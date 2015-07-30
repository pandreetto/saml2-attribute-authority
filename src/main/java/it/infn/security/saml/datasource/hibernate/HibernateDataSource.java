package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.AttributeEntityId;
import it.infn.security.saml.datasource.jpa.ResourceEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity.ResourceType;
import it.infn.security.saml.datasource.jpa.UserEntity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.wso2.charon.core.attributes.ComplexAttribute;
import org.wso2.charon.core.attributes.MultiValuedAttribute;
import org.wso2.charon.core.attributes.SimpleAttribute;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.DuplicateResourceException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.User;

public class HibernateDataSource
    implements DataSource {

    private static final Logger logger = Logger.getLogger(HibernateDataSource.class.getName());

    /*
     * Definitions for specific attribute structures
     */
    private final static String SPID_ATTR_NAME = "SPIDAttributes";

    private final static String KEY_FIELD = "key";

    private final static String CONTENT_FIELD = "content";

    private final static String ATTR_DESCR_FIELD = "description";

    private static SessionFactory sessionFactory;

    public HibernateDataSource() {
    }

    public void init()
        throws DataSourceException {

        try {

            StandardServiceRegistryBuilder serviceRegistryBuilder = new StandardServiceRegistryBuilder();
            serviceRegistryBuilder.applySettings(HibernateUtils.getHibernateConfig().getProperties());
            sessionFactory = HibernateUtils.getHibernateConfig().buildSessionFactory(serviceRegistryBuilder.build());

        } catch (Throwable th) {
            logger.log(Level.SEVERE, "Cannot initialize database", th);
            throw new DataSourceException("Cannot initialize database", th);
        }

    }

    public List<Attribute> findAttributes(String id, List<Attribute> requiredAttrs)
        throws DataSourceException {

        ArrayList<Attribute> result = new ArrayList<Attribute>();

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        AttributeBuilder attributeBuilder = (AttributeBuilder) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        XSStringBuilder attributeValueBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            String qStr = "SELECT qUser.id FROM UserEntity as qUser WHERE qUser.userName = :uName";
            Query query2 = session.createQuery(qStr).setString("uName", id);
            Long userId = (Long) query2.uniqueResult();
            if (userId == null) {
                logger.info("Entity not found " + id);
                /*
                 * TODO empty list or error?
                 */
                // session.getTransaction().commit();
                throw new DataSourceException("User not found");
            }

            HashSet<Long> allIds = getAllGroupIds(session, userId);
            allIds.add(userId);

            HashMap<String, Object> qArgs = new HashMap<String, Object>();
            StringBuffer queryStr = new StringBuffer("SELECT qAttributes");
            queryStr.append(" FROM ResourceEntity as qRes INNER JOIN qRes.attributes as qAttributes");

            queryStr.append(" WHERE qRes.id IN (:resourceIds)");
            qArgs.put("resourceIds", allIds);

            if (requiredAttrs != null && requiredAttrs.size() > 0) {
                queryStr.append(" AND (");
                int keyNum = 0;
                for (Attribute reqAttr : requiredAttrs) {
                    String tmpName = reqAttr.getName();
                    List<XMLObject> tmpValues = reqAttr.getAttributeValues();

                    if (keyNum > 0) {
                        queryStr.append(" OR");
                    }
                    String keyTag = "key_" + keyNum;
                    keyNum++;

                    if (tmpValues != null && tmpValues.size() > 0) {
                        int cntNum = 0;
                        for (XMLObject xObj : tmpValues) {

                            if (cntNum > 0) {
                                queryStr.append(" OR");
                            }
                            String refValue = xObj.getDOM().getTextContent().trim();

                            queryStr.append(" (qAttributes.attributeId.key = :").append(keyTag);
                            qArgs.put(keyTag, tmpName);

                            String cntTag = "cnt_" + keyNum + "_" + cntNum;
                            queryStr.append(" AND qAttributes.attributeId.content = :");
                            queryStr.append(cntTag).append(")");
                            qArgs.put(cntTag, refValue);
                            cntNum++;
                        }
                    } else {
                        queryStr.append(" qAttributes.attributeId.key = :").append(keyTag);
                        qArgs.put(keyTag, tmpName);
                    }
                }

                queryStr.append(")");
            }

            Query query = session.createQuery(queryStr.toString());
            query.setProperties(qArgs);

            @SuppressWarnings("unchecked")
            List<AttributeEntity> filteredAttrs = query.list();

            HashMap<String, Attribute> resultTable = new HashMap<String, Attribute>();
            for (AttributeEntity attrEnt : filteredAttrs) {

                String attrKey = attrEnt.getAttributeId().getKey();
                Attribute attribute = null;
                if (resultTable.containsKey(attrKey)) {
                    attribute = resultTable.get(attrKey);
                } else {
                    attribute = attributeBuilder.buildObject();
                    attribute.setName(attrKey);
                    attribute.setNameFormat(Attribute.BASIC);
                    resultTable.put(attrKey, attribute);
                }

                XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                        XSString.TYPE_NAME);
                attributeValue.setValue(attrEnt.getAttributeId().getContent());
                attribute.getAttributeValues().add(attributeValue);

            }

            for (Attribute tmpAttr : resultTable.values()) {
                result.add(tmpAttr);
            }

            session.getTransaction().commit();

        } catch (Throwable th) {

            session.getTransaction().rollback();

            logger.log(Level.SEVERE, th.getMessage(), th);

        }

        return result;
    }

    public void close()
        throws DataSourceException {

    }

    public User getUser(String userId)
        throws CharonException {

        User result = null;
        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();
            UserEntity usrEnt = (UserEntity) session.get(UserEntity.class, Long.parseLong(userId));
            if (usrEnt == null) {
                logger.info("Entity not found " + userId);
                /*
                 * TODO empty list or error?
                 */
                // session.getTransaction().commit();
                throw new DataSourceException("User not found");
            }

            result = userFromEntity(session, usrEnt);
            session.getTransaction().commit();

        } catch (Throwable th) {
            session.getTransaction().rollback();
        }
        return result;
    }

    public List<User> listUsers()
        throws CharonException {
        return null;
    }

    public List<User> listUsersByAttribute(org.wso2.charon.core.attributes.Attribute attribute) {
        return null;
    }

    public List<User> listUsersByFilter(String filter, String operation, String value)
        throws CharonException {
        return null;
    }

    public List<User> listUsersBySort(String sortBy, String sortOrder) {
        return null;
    }

    public List<User> listUsersWithPagination(int startIndex, int count) {
        return null;
    }

    public User updateUser(User user)
        throws CharonException {
        return null;
    }

    public User updateUser(List<org.wso2.charon.core.attributes.Attribute> updatedAttributes) {
        return null;
    }

    public void deleteUser(String userId)
        throws NotFoundException, CharonException {

    }

    public User createUser(User user)
        throws CharonException, DuplicateResourceException {
        return createUser(user, false);
    }

    public User createUser(User user, boolean isBulkUserAdd)
        throws CharonException, DuplicateResourceException {

        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            UserEntity eUser = new UserEntity();
            eUser.setType(ResourceType.USER);
            eUser.setUserName(user.getUserName());
            eUser.setCommonName(user.getGivenName() + " " + user.getFamilyName());

            Set<AttributeEntity> eUserAttrs = new HashSet<AttributeEntity>();

            org.wso2.charon.core.attributes.Attribute extAttribute = user.getAttribute(SPID_ATTR_NAME);
            for (org.wso2.charon.core.attributes.Attribute subAttr : ((MultiValuedAttribute) extAttribute)
                    .getValuesAsSubAttributes()) {
                ComplexAttribute cplxAttr = (ComplexAttribute) subAttr;
                SimpleAttribute keyAttr = (SimpleAttribute) cplxAttr.getSubAttribute(KEY_FIELD);
                SimpleAttribute cntAttr = (SimpleAttribute) cplxAttr.getSubAttribute(CONTENT_FIELD);
                SimpleAttribute descrAttr = (SimpleAttribute) cplxAttr.getSubAttribute(ATTR_DESCR_FIELD);

                AttributeEntity attrEnt = new AttributeEntity();
                AttributeEntityId attrEntId = new AttributeEntityId();
                attrEntId.setKey(keyAttr.getStringValue());
                attrEntId.setContent(cntAttr.getStringValue());
                attrEnt.setAttributeId(attrEntId);
                attrEnt.setDescription(descrAttr.getStringValue());

                /*
                 * TODO check for attribute auto-saving
                 */
                if (session.get(AttributeEntity.class, attrEntId) == null) {
                    logger.info("Saving attribute " + attrEnt.getAttributeId().getKey());
                    session.save(attrEnt);
                }

                eUserAttrs.add(attrEnt);

            }

            eUser.setAttributes(eUserAttrs);

            Long genId = (Long) session.save(eUser);
            logger.info("Created user " + user.getUserName() + " with id " + genId.toString());

            session.getTransaction().commit();

            return user;

        } catch (Throwable th) {

            /*
             * TODO check rollback
             */
            session.getTransaction().rollback();

            logger.log(Level.SEVERE, "Query execution error", th);
            throw new CharonException("Query execution error");
        }
    }

    public Group getGroup(String groupId)
        throws CharonException {
        return null;
    }

    public List<Group> listGroups()
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsByAttribute(org.wso2.charon.core.attributes.Attribute attribute)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsByFilter(String filter, String operation, String value)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsBySort(String sortBy, String sortOrder)
        throws CharonException {
        return null;
    }

    public List<Group> listGroupsWithPagination(int startIndex, int count) {
        return null;
    }

    public Group createGroup(Group group)
        throws CharonException, DuplicateResourceException {
        return null;
    }

    public Group updateGroup(Group oldGroup, Group group)
        throws CharonException {
        return null;
    }

    public Group patchGroup(Group oldGroup, Group group)
        throws CharonException {
        return null;
    }

    public Group updateGroup(List<org.wso2.charon.core.attributes.Attribute> attributes)
        throws CharonException {
        return null;
    }

    public void deleteGroup(String groupId)
        throws NotFoundException, CharonException {

    }

    private HashSet<ResourceEntity> getDirectGroups(Session session, ResourceEntity resource) {
        StringBuffer queryStr = new StringBuffer("SELECT resource.groups");
        queryStr.append(" FROM ResourceEntity as resource WHERE resource.id=?");
        Query query = session.createQuery(queryStr.toString());
        @SuppressWarnings("unchecked")
        List<ResourceEntity> idList = query.setLong(0, resource.getId()).list();
        return new HashSet<ResourceEntity>(idList);
    }

    private HashSet<ResourceEntity> getIndirectGroups(Session session, HashSet<ResourceEntity> resources) {
        return null;
    }

    private HashSet<ResourceEntity> getAllGroups(Session session, ResourceEntity resource) {
        HashSet<ResourceEntity> directGroups = getDirectGroups(session, resource);
        HashSet<ResourceEntity> result = getIndirectGroups(session, directGroups);
        result.addAll(directGroups);
        return result;
    }

    private HashSet<Long> getDirectGroupIds(Session session, Long resId) {
        StringBuffer queryStr = new StringBuffer("SELECT rGroups.id");
        queryStr.append(" FROM ResourceEntity as resource INNER JOIN resource.groups as rGroups");
        queryStr.append(" WHERE resource.id=?");
        Query query = session.createQuery(queryStr.toString());
        @SuppressWarnings("unchecked")
        List<Long> idList = query.setLong(0, resId).list();
        return new HashSet<Long>(idList);
    }

    private HashSet<Long> getIndirectGroupIds(Session session, HashSet<Long> resIds) {
        HashSet<Long> result = new HashSet<Long>();
        HashSet<Long> currSet = resIds;
        while (currSet.size() > 0) {
            StringBuffer queryStr = new StringBuffer("SELECT rGroups.id");
            queryStr.append(" FROM ResourceEntity as resource INNER JOIN resource.groups as rGroups");
            queryStr.append(" WHERE resource.id IN (:resourceIds)");
            Query query = session.createQuery(queryStr.toString());
            @SuppressWarnings("unchecked")
            List<Long> idList = query.setParameterList("resourceIds", currSet).list();
            currSet = new HashSet<Long>(idList);
            currSet.remove(result);
            result.addAll(idList);
        }

        return result;
    }

    private HashSet<Long> getAllGroupIds(Session session, Long resId) {
        HashSet<Long> directGroupIds = getDirectGroupIds(session, resId);
        HashSet<Long> result = getIndirectGroupIds(session, directGroupIds);
        result.addAll(directGroupIds);
        return result;
    }

    private User userFromEntity(Session session, UserEntity usrEnt)
        throws CharonException {
        User result = new User();
        result.setId(usrEnt.getId().toString());
        result.setUserName(usrEnt.getUserName());

        HashSet<Long> dGroups = getDirectGroupIds(session, usrEnt.getId());
        HashSet<Long> iGroups = getIndirectGroupIds(session, dGroups);

        ArrayList<String> tmpl1 = new ArrayList<String>(dGroups.size());
        for (Long tmpId : dGroups) {
            tmpl1.add(tmpId.toString());
        }
        result.setDirectGroups(tmpl1);

        ArrayList<String> tmpl2 = new ArrayList<String>(iGroups.size());
        for (Long tmpId : iGroups) {
            tmpl2.add(tmpId.toString());
        }
        result.setIndirectGroups(tmpl2);
        return result;
    }

}