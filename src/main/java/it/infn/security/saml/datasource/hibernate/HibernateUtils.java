package it.infn.security.saml.datasource.hibernate;

import java.util.UUID;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.GroupEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity;
import it.infn.security.saml.datasource.jpa.UserEntity;

import org.hibernate.cfg.Configuration;

public class HibernateUtils {

    private static Configuration hiberCfg = null;

    private static String[] hiberCfgMParams = { "hibernate.connection.driver_class", "hibernate.connection.url",
            "hibernate.connection.username", "hibernate.connection.password" };

    private static String[] hiberCfgOParams = { "hibernate.dialect", "hibernate.connection.pool_size",
            "hibernate.current_session_context_class", "hibernate.cache.provider_class", "hibernate.show_sql",
            "hibernate.hbm2ddl.auto" };

    public static Configuration getHibernateConfig()
        throws ConfigurationException {

        if (hiberCfg != null) {
            return hiberCfg;
        }

        synchronized (HibernateUtils.class) {

            if (hiberCfg == null) {
                AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();

                hiberCfg = new Configuration();

                for (String param : hiberCfgMParams) {
                    String tmppar = config.getDataSourceParam(param);
                    if (tmppar == null) {
                        throw new ConfigurationException("Missing parameter " + param);
                    }
                    hiberCfg.setProperty(param, tmppar);
                }

                for (String param : hiberCfgOParams) {
                    String tmppar = config.getDataSourceParam(param);
                    if (tmppar != null) {
                        hiberCfg.setProperty(param, tmppar);
                    }
                }

                hiberCfg.addAnnotatedClass(ResourceEntity.class);
                hiberCfg.addAnnotatedClass(AttributeEntity.class);
                hiberCfg.addAnnotatedClass(UserEntity.class);
                hiberCfg.addAnnotatedClass(GroupEntity.class);
            }

        }

        return hiberCfg;

    }

    public static String convertSortedParam(String sParam, boolean isUser) {

        if (sParam == null)
            return null;

        sParam = sParam.toLowerCase();

        /*
         * TODO user introspection for collecting db-fields
         */
        if (sParam.equals("id"))
            return "id";

        if (isUser) {
            if (sParam.equals("username"))
                return "userName";
            if (sParam.equals("commonname"))
                return "commonName";
        } else {
            if (sParam.equals("displayname"))
                return "displayName";
        }

        throw new IllegalArgumentException("Wrong parameter " + sParam);
    }

    /*
     * TODO read system max user and group count from configuration
     */
    private static int MAXUSERPERPAGE = 100;

    private static int MAXGROUPPERPAGE = 100;

    public static int checkQueryRange(int count, boolean isUser) {
        if (isUser) {
            return (count > MAXUSERPERPAGE || count <= 0) ? MAXUSERPERPAGE : count;
        } else {
            return (count > MAXGROUPPERPAGE || count <= 0) ? MAXGROUPPERPAGE : count;
        }
    }
    
    public static String generateNewVersion(String currVer) {
        return UUID.randomUUID().toString();
    }

}