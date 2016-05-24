package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.AddrValueTuple;
import it.infn.security.saml.datasource.AttrValueTuple;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.UserResource;
import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.ExternalIdEntity;
import it.infn.security.saml.datasource.jpa.GroupEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity;
import it.infn.security.saml.datasource.jpa.UserAddressEntity;
import it.infn.security.saml.datasource.jpa.UserAttributeEntity;
import it.infn.security.saml.datasource.jpa.UserEntity;
import it.infn.security.scim.core.SCIMCoreConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

import org.hibernate.cfg.Configuration;

public class HibernateUtils {

    private static final Logger logger = Logger.getLogger(HibernateUtils.class.getName());

    private static Configuration hiberCfg = null;

    private static String[] hiberCfgMParams = { "hibernate.connection.driver_class", "hibernate.connection.url",
            "hibernate.connection.username", "hibernate.connection.password" };

    public static Configuration getHibernateConfig()
        throws ConfigurationException {

        if (hiberCfg != null) {
            return hiberCfg;
        }

        synchronized (HibernateUtils.class) {

            if (hiberCfg == null) {
                AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();

                hiberCfg = new Configuration();

                HashMap<String, Object> hiberParamMap = config.getDataSourceParamMap("hibernate.");

                for (String param : hiberCfgMParams) {
                    if (!hiberParamMap.containsKey(param)) {
                        throw new ConfigurationException("Missing parameter " + param);
                    }
                }

                for (String kName : hiberParamMap.keySet()) {
                    String kValue = hiberParamMap.get(kName).toString();
                    hiberCfg.setProperty(kName, kValue);
                    logger.info("Set hibernate parameter " + kName + " to " + kValue);
                }

                hiberCfg.addAnnotatedClass(ResourceEntity.class);
                hiberCfg.addAnnotatedClass(AttributeEntity.class);
                hiberCfg.addAnnotatedClass(UserEntity.class);
                hiberCfg.addAnnotatedClass(GroupEntity.class);
                hiberCfg.addAnnotatedClass(ExternalIdEntity.class);
                hiberCfg.addAnnotatedClass(UserAttributeEntity.class);
                hiberCfg.addAnnotatedClass(UserAddressEntity.class);
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

    public static int checkQueryRange(int count, boolean isUser) {

        int pSize = 100;

        try {
            AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();
            pSize = isUser ? config.getUserPageSize() : config.getGroupPageSize();
        } catch (ConfigurationException cEx) {
            logger.severe(cEx.getMessage());
        }

        return (count > pSize || count <= 0) ? pSize : count;
    }

    public static String generateNewVersion(String currVer) {
        return UUID.randomUUID().toString();
    }

    public static void copyAttributesInEntity(UserResource userRes, UserEntity eUser)
        throws DataSourceException {

        HashMap<String, String> attrTable = new HashMap<String, String>();
        attrTable.put(SCIMCoreConstants.GIVEN_NAME, userRes.getUserGivenName());
        attrTable.put(SCIMCoreConstants.FAMILY_NAME, userRes.getUserFamilyName());
        attrTable.put(SCIMCoreConstants.MIDDLE_NAME, userRes.getUserMiddleName());
        attrTable.put(SCIMCoreConstants.DISPLAY_NAME, userRes.getUserDisplayName());
        attrTable.put(SCIMCoreConstants.HONORIFIC_PREFIX, userRes.getUserHonorPrefix());
        attrTable.put(SCIMCoreConstants.HONORIFIC_SUFFIX, userRes.getUserHonorSuffix());
        attrTable.put(SCIMCoreConstants.NICK_NAME, userRes.getUserNickName());
        attrTable.put(SCIMCoreConstants.TITLE, userRes.getUserTitle());
        attrTable.put(SCIMCoreConstants.PROFILE_URL, userRes.getUserURL());
        attrTable.put(SCIMCoreConstants.USER_TYPE, userRes.getUserPosition());
        attrTable.put(SCIMCoreConstants.PREFERRED_LANGUAGE, userRes.getUserLang());
        attrTable.put(SCIMCoreConstants.LOCALE, userRes.getUserLocale());
        attrTable.put(SCIMCoreConstants.TIME_ZONE, userRes.getUserTimezone());
        attrTable.put(SCIMCoreConstants.PASSWORD, userRes.getUserPwd());

        for (String aKey : attrTable.keySet()) {
            String aValue = attrTable.get(aKey);
            if (aValue != null) {
                UserAttributeEntity attEnt = new UserAttributeEntity();
                attEnt.setKey(aKey);
                attEnt.setValue(aValue);
                attEnt.setType(null);
                attEnt.setUser(eUser);
                eUser.getUserAttributes().add(attEnt);
            }
        }

        List<UserAttributeEntity> emailList = getAttributeList(eUser, SCIMCoreConstants.EMAIL, userRes.getUserEmails());
        eUser.getUserAttributes().addAll(emailList);

        List<UserAttributeEntity> phoneList = getAttributeList(eUser, SCIMCoreConstants.PHONE_NUMBER,
                userRes.getUserPhones());
        eUser.getUserAttributes().addAll(phoneList);

        List<UserAttributeEntity> imList = getAttributeList(eUser, SCIMCoreConstants.IM, userRes.getUserIMs());
        eUser.getUserAttributes().addAll(imList);

        List<UserAttributeEntity> photoList = getAttributeList(eUser, SCIMCoreConstants.PHOTO, userRes.getUserPhotos());
        eUser.getUserAttributes().addAll(photoList);

        List<UserAttributeEntity> roleList = getAttributeList(eUser, SCIMCoreConstants.ROLE, userRes.getUserRoles());
        eUser.getUserAttributes().addAll(roleList);

        List<UserAttributeEntity> entitleList = getAttributeList(eUser, SCIMCoreConstants.ENTITLEMENT,
                userRes.getUserEntitles());
        eUser.getUserAttributes().addAll(entitleList);

        List<UserAttributeEntity> x509CertList = getAttributeList(eUser, SCIMCoreConstants.X509CERTIFICATE,
                userRes.getUserCertificates());
        eUser.getUserAttributes().addAll(x509CertList);

        for (AddrValueTuple aTuple : userRes.getUserAddresses()) {
            UserAddressEntity addEnt = new UserAddressEntity();
            addEnt.setUser(eUser);
            addEnt.setStreet(aTuple.getStreet());
            addEnt.setLocality(aTuple.getLocality());
            addEnt.setReqion(aTuple.getRegion());
            addEnt.setPostalCode(aTuple.getCode());
            addEnt.setCountry(aTuple.getCounty());
            addEnt.setType(aTuple.getType());
            eUser.getUserAddresses().add(addEnt);
        }

    }

    private static List<UserAttributeEntity> getAttributeList(UserEntity eUser, String itemName,
            List<AttrValueTuple> values)
        throws DataSourceException {
        List<UserAttributeEntity> result = new ArrayList<UserAttributeEntity>();
        for (AttrValueTuple vTuple : values) {
            UserAttributeEntity attEnt = new UserAttributeEntity();
            attEnt.setKey(itemName);
            attEnt.setValue(vTuple.getValue());
            attEnt.setType(vTuple.getType());
            attEnt.setUser(eUser);
            result.add(attEnt);
        }
        return result;
    }

    public static void copyAttributesInUser(UserEntity eUser, UserResource userRes)
        throws DataSourceException {

        for (UserAttributeEntity usrAttr : eUser.getUserAttributes()) {
            String key = usrAttr.getKey();
            if (key.equals(SCIMCoreConstants.GIVEN_NAME)) {

                userRes.setUserGivenName(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.FAMILY_NAME)) {

                userRes.setUserFamilyName(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.MIDDLE_NAME)) {

                userRes.setUserMiddleName(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.DISPLAY_NAME)) {

                userRes.setUserDisplayName(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.HONORIFIC_PREFIX)) {

                userRes.setUserHonorPrefix(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.HONORIFIC_SUFFIX)) {

                userRes.setUserHonorSuffix(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.NICK_NAME)) {

                userRes.setUserNickName(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.TITLE)) {

                userRes.setUserTitle(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.PROFILE_URL)) {

                userRes.setUserURL(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.USER_TYPE)) {

                userRes.setUserPosition(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.PREFERRED_LANGUAGE)) {

                userRes.setUserLang(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.LOCALE)) {

                userRes.setUserLocale(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.TIME_ZONE)) {

                userRes.setUserTimezone(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.PASSWORD)) {

                userRes.setUserPwd(usrAttr.getValue());

            } else if (key.equals(SCIMCoreConstants.EMAIL)) {

                userRes.addUserEmail(usrAttr.getValue(), usrAttr.getType());

            } else if (key.equals(SCIMCoreConstants.PHONE_NUMBER)) {

                userRes.addUserPhone(usrAttr.getValue(), usrAttr.getType());

            } else if (key.equals(SCIMCoreConstants.IM)) {

                userRes.addUserIM(usrAttr.getValue(), usrAttr.getType());

            } else if (key.equals(SCIMCoreConstants.PHOTO)) {

                userRes.addUserPhoto(usrAttr.getValue(), usrAttr.getType());

            } else if (key.equals(SCIMCoreConstants.ROLE)) {

                userRes.addUserRole(usrAttr.getValue(), usrAttr.getType());

            } else if (key.equals(SCIMCoreConstants.ENTITLEMENT)) {

                userRes.addUserEntitle(usrAttr.getValue(), usrAttr.getType());

            } else if (key.equals(SCIMCoreConstants.X509CERTIFICATE)) {

                userRes.addUserCertificate(usrAttr.getValue(), usrAttr.getType());

            }

        }

        for (UserAddressEntity addEnt : eUser.getUserAddresses()) {

            userRes.addUserAddress(addEnt.getStreet(), addEnt.getLocality(), addEnt.getRegion(),
                    addEnt.getPostalCode(), addEnt.getCountry(), addEnt.getType());
        }

    }

}