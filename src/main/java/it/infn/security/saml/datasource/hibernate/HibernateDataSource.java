package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.AttributeEntityId;
import it.infn.security.saml.datasource.jpa.ResourceEntity.ResourceType;
import it.infn.security.saml.datasource.jpa.UserEntity;

import java.util.ArrayList;
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

            ArrayList<String> qArgs = new ArrayList<String>();
            StringBuffer queryStr = new StringBuffer("select qAttributes");
            queryStr.append(" from UserEntity as qUser inner join qUser.attributes as qAttributes");

            queryStr.append(" where qUser.userName = ?");
            qArgs.add(id);

            if (requiredAttrs != null && requiredAttrs.size() > 0) {
                queryStr.append(" and (");
                boolean foundFirst = false;
                for (Attribute reqAttr : requiredAttrs) {
                    String tmpName = reqAttr.getName();
                    List<XMLObject> tmpValues = reqAttr.getAttributeValues();

                    if (foundFirst) {
                        queryStr.append(" or");
                    } else {
                        foundFirst = true;
                    }

                    if (tmpValues != null && tmpValues.size() > 0) {
                        for (XMLObject xObj : tmpValues) {
                            String refValue = xObj.getDOM().getTextContent().trim();

                            queryStr.append(" (qAttributes.attributeId.key = ?");
                            qArgs.add(tmpName);
                            queryStr.append(" and qAttributes.attributeId.content = ?)");
                            qArgs.add(refValue);
                        }
                    } else {
                        queryStr.append(" qAttributes.attributeId.key = ?");
                        qArgs.add(tmpName);
                    }
                }

                queryStr.append(")");
            }

            logger.info("Executing query: " + queryStr.toString());
            Query query = session.createQuery(queryStr.toString());
            for (int k = 0; k < qArgs.size(); k++) {
                query.setString(k, qArgs.get(k));
            }

            @SuppressWarnings("unchecked")
            List<AttributeEntity> filteredAttrs = query.list();

            if (filteredAttrs.size() == 0) {
                Query query2 = session.createQuery("from UserEntity as qUser where qUser.userName = :uName");
                UserEntity gUser = (UserEntity) query2.setString("uName", id).uniqueResult();
                if (gUser == null) {
                    logger.info("Entity not found " + id);
                    /*
                     * TODO empty list or error?
                     */
                    session.getTransaction().commit();
                    return result;
                }
            }

            for (AttributeEntity attrEnt : filteredAttrs) {
                Attribute attribute = attributeBuilder.buildObject();
                attribute.setName(attrEnt.getAttributeId().getKey());
                attribute.setNameFormat(Attribute.BASIC);
                XSString attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                        XSString.TYPE_NAME);
                attributeValue.setValue(attrEnt.getAttributeId().getContent());
                attribute.getAttributeValues().add(attributeValue);
                result.add(attribute);
            }

            /*
             * TODO attributes from groups
             */

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
        return null;
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

}