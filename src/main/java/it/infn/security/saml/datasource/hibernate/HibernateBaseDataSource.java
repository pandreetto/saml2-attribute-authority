package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;

import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.StatusCode;

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
                throw new DataSourceException("User not found", StatusCode.RESPONDER_URI,
                        StatusCode.UNKNOWN_PRINCIPAL_URI);
            }

            ResourceGraph rGraph = new ResourceGraph(session);
            HashSet<String> allIds = rGraph.getAllGroupIds(userId);
            allIds.add(userId);

            List<Attribute> result = buildAttributeList(session, allIds, requiredAttrs);

            session.getTransaction().commit();

            return result;

        } catch (DataSourceException dsEx) {

            logger.log(Level.SEVERE, dsEx.getMessage());
            session.getTransaction().rollback();
            throw dsEx;

        } catch (Throwable th) {

            logger.log(Level.SEVERE, th.getMessage(), th);
            session.getTransaction().rollback();
            throw new DataSourceException(th.getMessage());

        }

    }

    public void close()
        throws DataSourceException {

    }

    protected abstract List<Attribute> buildAttributeList(Session session, HashSet<String> allIds,
            List<Attribute> reqAttrs);

}