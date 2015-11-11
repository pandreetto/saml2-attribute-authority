package it.infn.security.saml.datasource.hibernate;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.jpa.AttributeEntity;
import it.infn.security.saml.datasource.jpa.ExternalIdEntity;
import it.infn.security.saml.datasource.jpa.GroupEntity;
import it.infn.security.saml.datasource.jpa.ResourceEntity;
import it.infn.security.saml.datasource.jpa.UserAddressEntity;
import it.infn.security.saml.datasource.jpa.UserAttributeEntity;
import it.infn.security.saml.datasource.jpa.UserEntity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.hibernate.cfg.Configuration;
import org.wso2.charon.core.attributes.Attribute;
import org.wso2.charon.core.attributes.ComplexAttribute;
import org.wso2.charon.core.attributes.MultiValuedAttribute;
import org.wso2.charon.core.attributes.SimpleAttribute;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.User;
import org.wso2.charon.core.schema.SCIMConstants;

public class HibernateUtils {

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
                    hiberCfg.setProperty(kName, hiberParamMap.get(kName).toString());
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

    public static void copyAttributesInEntity(User user, UserEntity eUser)
        throws CharonException, NotFoundException {

        HashMap<String, String> attrTable = new HashMap<String, String>();
        attrTable.put(SCIMConstants.UserSchemaConstants.GIVEN_NAME, user.getGivenName());
        attrTable.put(SCIMConstants.UserSchemaConstants.FAMILY_NAME, user.getFamilyName());
        attrTable.put(SCIMConstants.UserSchemaConstants.MIDDLE_NAME, user.getMiddleName());
        attrTable.put(SCIMConstants.UserSchemaConstants.DISPLAY_NAME, user.getDisplayName());
        attrTable.put(SCIMConstants.UserSchemaConstants.HONORIFIC_PREFIX, user.getHonorificPrefix());
        attrTable.put(SCIMConstants.UserSchemaConstants.HONORIFIC_SUFFIX, user.getHonorificSuffix());
        attrTable.put(SCIMConstants.UserSchemaConstants.NICK_NAME, user.getNickName());
        attrTable.put(SCIMConstants.UserSchemaConstants.TITLE, user.getTitle());
        attrTable.put(SCIMConstants.UserSchemaConstants.PROFILE_URL, user.getProfileURL());
        attrTable.put(SCIMConstants.UserSchemaConstants.USER_TYPE, user.getUserType());
        attrTable.put(SCIMConstants.UserSchemaConstants.PREFERRED_LANGUAGE, user.getPreferredLanguage());
        attrTable.put(SCIMConstants.UserSchemaConstants.LOCALE, user.getLocale());
        attrTable.put(SCIMConstants.UserSchemaConstants.TIME_ZONE, user.getTimeZone());
        attrTable.put(SCIMConstants.UserSchemaConstants.PASSWORD, user.getPassword());

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

        List<UserAttributeEntity> emailList = getTypedAttributeList(user, eUser,
                SCIMConstants.UserSchemaConstants.EMAILS, SCIMConstants.UserSchemaConstants.EMAIL);
        eUser.getUserAttributes().addAll(emailList);

        List<UserAttributeEntity> phoneList = getTypedAttributeList(user, eUser,
                SCIMConstants.UserSchemaConstants.PHONE_NUMBERS, SCIMConstants.UserSchemaConstants.PHONE_NUMBER);
        eUser.getUserAttributes().addAll(phoneList);

        List<UserAttributeEntity> imList = getTypedAttributeList(user, eUser, SCIMConstants.UserSchemaConstants.IMS,
                SCIMConstants.UserSchemaConstants.IM);
        eUser.getUserAttributes().addAll(imList);

        List<UserAttributeEntity> photoList = getTypedAttributeList(user, eUser, "photos", "photo");
        eUser.getUserAttributes().addAll(photoList);

        List<UserAttributeEntity> roleList = getTypedAttributeList(user, eUser, "roles", "role");
        eUser.getUserAttributes().addAll(roleList);

        List<UserAttributeEntity> entitleList = getTypedAttributeList(user, eUser, "entitlements", "entitlement");
        eUser.getUserAttributes().addAll(entitleList);

        /*
         * TODO x509Certificates
         */

        if (user.isAttributeExist(SCIMConstants.UserSchemaConstants.ADDRESSES)) {
            MultiValuedAttribute addresses = (MultiValuedAttribute) user.getAttributeList().get(
                    SCIMConstants.UserSchemaConstants.ADDRESSES);
            for (Map<String, Object> addrItem : addresses.getComplexValues()) {
                UserAddressEntity addEnt = new UserAddressEntity();
                addEnt.setUser(eUser);
                addEnt.setStreet(addrItem.get(SCIMConstants.UserSchemaConstants.STREET_ADDRESS).toString());
                addEnt.setLocality(addrItem.get(SCIMConstants.UserSchemaConstants.LOCALITY).toString());
                addEnt.setReqion(addrItem.get(SCIMConstants.UserSchemaConstants.REGION).toString());
                addEnt.setPostalCode(addrItem.get(SCIMConstants.UserSchemaConstants.POSTAL_CODE).toString());
                addEnt.setCountry(addrItem.get(SCIMConstants.UserSchemaConstants.COUNTRY).toString());
                addEnt.setType(addrItem.get(SCIMConstants.CommonSchemaConstants.TYPE).toString());
                eUser.getUserAddresses().add(addEnt);
            }
        }
    }

    private static List<UserAttributeEntity> getTypedAttributeList(User user, UserEntity eUser, String categName,
            String itemName)
        throws CharonException {
        List<UserAttributeEntity> result = new ArrayList<UserAttributeEntity>();

        if (user.isAttributeExist(categName)) {

            MultiValuedAttribute mAttr = (MultiValuedAttribute) user.getAttributeList().get(categName);
            if (mAttr.getValuesAsStrings() != null && mAttr.getValuesAsStrings().size() != 0) {
                for (String tmpValue : mAttr.getValuesAsStrings()) {
                    UserAttributeEntity attEnt = new UserAttributeEntity();
                    attEnt.setKey(itemName);
                    attEnt.setValue(tmpValue);
                    attEnt.setType(null);
                    attEnt.setUser(eUser);
                    result.add(attEnt);
                }

            } else {

                List<Attribute> subAttributes = mAttr.getValuesAsSubAttributes();
                if (subAttributes != null && subAttributes.size() != 0) {
                    for (Attribute subAttribute : subAttributes) {

                        UserAttributeEntity attEnt = new UserAttributeEntity();
                        attEnt.setKey(itemName);
                        attEnt.setUser(eUser);

                        if (subAttribute instanceof SimpleAttribute) {
                            SimpleAttribute valueAttribute = (SimpleAttribute) subAttribute;
                            attEnt.setValue((String) valueAttribute.getValue());
                            attEnt.setType(null);
                        } else if (subAttribute instanceof ComplexAttribute) {
                            ComplexAttribute cplxAttr = (ComplexAttribute) subAttribute;

                            SimpleAttribute valueAttribute = (SimpleAttribute) (cplxAttr
                                    .getSubAttribute(SCIMConstants.CommonSchemaConstants.VALUE));
                            attEnt.setValue((String) valueAttribute.getValue());

                            SimpleAttribute typeAttribute = (SimpleAttribute) (cplxAttr
                                    .getSubAttribute(SCIMConstants.CommonSchemaConstants.TYPE));
                            if (typeAttribute != null) {
                                attEnt.setType((String) typeAttribute.getValue());
                            }
                        }

                        result.add(attEnt);
                    }
                }
            }
        }

        return result;
    }

    public static void copyAttributesInUser(UserEntity eUser, User user)
        throws CharonException {

        for (UserAttributeEntity usrAttr : eUser.getUserAttributes()) {
            String key = usrAttr.getKey();
            if (key.equals(SCIMConstants.UserSchemaConstants.GIVEN_NAME)) {
                user.setGivenName(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.FAMILY_NAME)) {
                user.setFamilyName(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.MIDDLE_NAME)) {
                user.setMiddleName(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.DISPLAY_NAME)) {
                user.setDisplayName(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.HONORIFIC_PREFIX)) {
                user.setHonorificPrefix(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.HONORIFIC_SUFFIX)) {
                user.setHonorificSuffix(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.NICK_NAME)) {
                user.setNickName(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.TITLE)) {
                user.setTitle(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.PROFILE_URL)) {
                user.setProfileURL(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.USER_TYPE)) {
                user.setUserType(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.PREFERRED_LANGUAGE)) {
                user.setPreferredLanguage(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.LOCALE)) {
                user.setLocale(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.TIME_ZONE)) {
                user.setTimeZone(usrAttr.getValue());
            } else if (key.equals(SCIMConstants.UserSchemaConstants.PASSWORD)) {
                user.setPassword(usrAttr.getValue());
            }
        }

    }

}