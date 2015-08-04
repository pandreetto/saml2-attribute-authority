package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.jpa.AttributeEntity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
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

public abstract class HibernateBaseDataSource
    implements DataSource {

    private static final Logger logger = Logger.getLogger(HibernateBaseDataSource.class.getName());

    protected static SessionFactory sessionFactory;

    public HibernateBaseDataSource() {
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

        Session session = sessionFactory.getCurrentSession();

        try {

            session.beginTransaction();

            String qStr = "SELECT qUser.id FROM UserEntity as qUser WHERE qUser.userName = :uName";
            Query query2 = session.createQuery(qStr).setString("uName", id);
            String userId = (String) query2.uniqueResult();
            if (userId == null) {
                logger.info("Entity not found " + id);
                /*
                 * TODO empty list or error?
                 */
                // session.getTransaction().commit();
                throw new DataSourceException("User not found");
            }

            HashSet<String> allIds = getAllGroupIds(session, userId);
            allIds.add(userId);

            List<Attribute> result = buildAttributeList(session, allIds, requiredAttrs);

            session.getTransaction().commit();

            return result;

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);

            session.getTransaction().rollback();

            throw new DataSourceException(th.getMessage());

        }

    }

    public void close()
        throws DataSourceException {

    }

    protected HashSet<String> getDirectGroupIds(Session session, String resId) {
        StringBuffer queryStr = new StringBuffer("SELECT rGroups.id");
        queryStr.append(" FROM ResourceEntity as resource INNER JOIN resource.groups as rGroups");
        queryStr.append(" WHERE resource.id=?");
        Query query = session.createQuery(queryStr.toString());
        @SuppressWarnings("unchecked")
        List<String> idList = query.setString(0, resId).list();
        return new HashSet<String>(idList);
    }

    protected HashSet<String> getIndirectGroupIds(Session session, HashSet<String> resIds) {
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

    protected HashSet<String> getAllGroupIds(Session session, String resId) {
        HashSet<String> directGroupIds = getDirectGroupIds(session, resId);
        HashSet<String> result = getIndirectGroupIds(session, directGroupIds);
        result.addAll(directGroupIds);
        return result;
    }

    /*
     * TODO move the section below into subclass
     */
    protected final static String SPID_ATTR_NAME = "SPIDAttributes";

    protected final static String KEY_FIELD = "key";

    protected final static String CONTENT_FIELD = "content";

    protected final static String ATTR_DESCR_FIELD = "description";

    protected List<Attribute> buildAttributeList(Session session, HashSet<String> allIds, List<Attribute> reqAttrs) {

        ArrayList<Attribute> result = new ArrayList<Attribute>();

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        AttributeBuilder attributeBuilder = (AttributeBuilder) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        XSStringBuilder attributeValueBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

        HashMap<String, Object> qArgs = new HashMap<String, Object>();
        StringBuffer queryStr = new StringBuffer("SELECT qAttributes");
        queryStr.append(" FROM ResourceEntity as qRes INNER JOIN qRes.attributes as qAttributes");

        queryStr.append(" WHERE qRes.id IN (:resourceIds)");
        qArgs.put("resourceIds", allIds);

        if (reqAttrs != null && reqAttrs.size() > 0) {
            queryStr.append(" AND (");
            int keyNum = 0;
            for (Attribute reqAttr : reqAttrs) {
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

        return result;
    }

}