package it.infn.security.scim.core;

import it.infn.security.saml.datasource.AddrValueTuple;
import it.infn.security.saml.datasource.AttrValueTuple;
import it.infn.security.saml.datasource.DataSourceException;

import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.json.Json;
import javax.json.stream.JsonParser;
import javax.json.stream.JsonParsingException;

public class SCIM2Decoder {

    private static String getKeyName(JsonParser jParser)
        throws JsonParsingException {
        /*
         * TODO implement check for SCIM 2.0
         */
        return jParser.getString();
    }

    private static void checkSchemas(JsonParser jParser, Set<String> schemas) {
        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_ARRAY; evn = jParser.next()) {
            if (evn == JsonParser.Event.VALUE_STRING) {
                schemas.add(jParser.getString());
            } else {
                throw new JsonParsingException("Bad schema definition", jParser.getLocation());
            }
        }
    }

    private static void checkResAttribute(JsonParser jParser, SCIM2Resource resource, String kName, String value)
        throws DataSourceException {

        if (SCIMCoreConstants.ID.equals(kName)) {
            resource.setResourceId(value);
        } else if (SCIMCoreConstants.EXTERNAL_ID.equals(kName)) {
            resource.setResourceExtId(value);
        } else {
            throw new JsonParsingException("Attribute not recognized " + kName, jParser.getLocation());
        }

    }

    private static void checkMeta(SCIM2Resource resource, JsonParser jParser)
        throws DataSourceException {

        SimpleDateFormat dParser = new SimpleDateFormat(SCIMCoreConstants.DATE_PATTERN);
        String keyName = null;

        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_OBJECT; evn = jParser.next()) {

            if (evn == JsonParser.Event.KEY_NAME) {
                keyName = getKeyName(jParser);
                continue;
            }

            if (evn != JsonParser.Event.VALUE_STRING) {
                throw new JsonParsingException("Wrong meta attribute", jParser.getLocation());
            }

            try {
                if (SCIMCoreConstants.CREATED.equals(keyName)) {
                    resource.setResourceCreationDate(dParser.parse(jParser.getString()));
                } else if (SCIMCoreConstants.MODIFIED.equals(keyName)) {
                    resource.setResourceChangeDate(dParser.parse(jParser.getString()));
                } else if (SCIMCoreConstants.VERSION.equals(keyName)) {
                    resource.setResourceVersion(jParser.getString());
                }
            } catch (Exception ex) {
                throw new JsonParsingException(ex.getMessage(), jParser.getLocation());
            }
        }
    }

    private static void checkAttribute(JsonParser jParser, SCIM2User user, String kName, String value)
        throws DataSourceException {

        if (SCIMCoreConstants.USER_NAME.equals(kName)) {
            user.setName(value);
        } else if (SCIMCoreConstants.DISPLAY_NAME.equals(kName)) {
            user.setUserDisplayName(value);
        } else if (SCIMCoreConstants.NICK_NAME.equals(kName)) {
            user.setUserNickName(value);
        } else if (SCIMCoreConstants.PROFILE_URL.equals(kName)) {
            user.setUserURL(value);
        } else if (SCIMCoreConstants.TITLE.equals(kName)) {
            user.setUserTitle(value);
        } else if (SCIMCoreConstants.USER_TYPE.equals(kName)) {
            user.setUserPosition(value);
        } else if (SCIMCoreConstants.PREFERRED_LANGUAGE.equals(kName)) {
            user.setUserLang(value);
        } else if (SCIMCoreConstants.LOCALE.equals(kName)) {
            user.setUserLocale(value);
        } else if (SCIMCoreConstants.TIME_ZONE.equals(kName)) {
            user.setUserTimezone(value);
        } else if (SCIMCoreConstants.PASSWORD.equals(kName)) {
            user.setUserPwd(value);
        } else {

            checkResAttribute(jParser, user, kName, value);

        }

    }

    private static void checkAttribute(JsonParser jParser, SCIM2Group group, String kName, String value)
        throws DataSourceException {
        if (SCIMCoreConstants.DISPLAY_NAME.equals(kName)) {
        } else {

            checkResAttribute(jParser, group, kName, value);

        }

    }

    private static void checkSubAttribute(JsonParser jParser, List<AttrValueTuple> attrList) {

        String kName = null;
        String aValue = null;
        String aType = null;

        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_OBJECT; evn = jParser.next()) {

            if (evn == JsonParser.Event.KEY_NAME) {
                kName = getKeyName(jParser);
            } else if (evn == JsonParser.Event.VALUE_STRING) {
                if (SCIMCoreConstants.VALUE.equals(kName)) {
                    aValue = jParser.getString();
                } else if (SCIMCoreConstants.PRIMARY.equals(kName)) {
                    // ignored
                } else if (SCIMCoreConstants.TYPE.equals(kName)) {
                    aType = jParser.getString();
                } else if (SCIMCoreConstants.DISPLAY.equals(kName)) {
                    // ignored
                } else {
                    throw new JsonParsingException("Wrong subattribute format", jParser.getLocation());
                }
            } else {
                throw new JsonParsingException("Wrong subattribute format", jParser.getLocation());
            }
        }

        attrList.add(new AttrValueTuple(aValue, aType));
    }

    private static void checkStdMultiValue(JsonParser jParser, SCIM2User user, String kName)
        throws DataSourceException {

        List<AttrValueTuple> attrList = new ArrayList<AttrValueTuple>();

        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_ARRAY; evn = jParser.next()) {

            if (evn == JsonParser.Event.VALUE_STRING) {
                // primitive value
                attrList.add(new AttrValueTuple(jParser.getString(), "undefined"));
            } else if (evn == JsonParser.Event.START_OBJECT) {
                // complex value
                checkSubAttribute(jParser, attrList);
            } else {
                throw new JsonParsingException("Wrong json format", jParser.getLocation());
            }
        }

        if (SCIMCoreConstants.EMAILS.equals(kName)) {
            for (AttrValueTuple aTuple : attrList) {
                user.addUserEmail(aTuple.getValue(), aTuple.getType());
            }
        } else if (SCIMCoreConstants.PHONE_NUMBERS.equals(kName)) {
            for (AttrValueTuple aTuple : attrList) {
                user.addUserPhone(aTuple.getValue(), aTuple.getType());
            }
        } else if (SCIMCoreConstants.IMS.equals(kName)) {
            for (AttrValueTuple aTuple : attrList) {
                user.addUserIM(aTuple.getValue(), aTuple.getType());
            }
        } else if (SCIMCoreConstants.PHOTOS.equals(kName)) {
            for (AttrValueTuple aTuple : attrList) {
                user.addUserPhoto(aTuple.getValue(), aTuple.getType());
            }
        } else if (SCIMCoreConstants.ENTITLEMENTS.equals(kName)) {
            for (AttrValueTuple aTuple : attrList) {
                user.addUserEntitle(aTuple.getValue(), aTuple.getType());
            }
        } else if (SCIMCoreConstants.ROLES.equals(kName)) {
            for (AttrValueTuple aTuple : attrList) {
                user.addUserRole(aTuple.getValue(), aTuple.getType());
            }
        } else if (SCIMCoreConstants.X509CERTIFICATES.equals(kName)) {
            for (AttrValueTuple aTuple : attrList) {
                user.addUserCertificate(aTuple.getValue(), aTuple.getType());
            }
        } else {
            throw new JsonParsingException("Attribute not recognized " + kName, jParser.getLocation());
        }
    }

    private static void checkAddresses(JsonParser jParser, SCIM2User user)
        throws DataSourceException {

        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_ARRAY; evn = jParser.next()) {

            if (evn != JsonParser.Event.START_OBJECT) {
                throw new JsonParsingException("Wrong json format", jParser.getLocation());
            }

            String kName = null;
            AddrValueTuple addrTuple = new AddrValueTuple();
            for (JsonParser.Event evn2 = jParser.next(); evn2 != JsonParser.Event.END_OBJECT; evn2 = jParser.next()) {

                if (evn2 == JsonParser.Event.KEY_NAME) {
                    kName = getKeyName(jParser);
                } else if (evn2 == JsonParser.Event.VALUE_STRING) {

                    if (SCIMCoreConstants.STREET.equals(kName)) {
                        addrTuple.setStreet(jParser.getString());
                    } else if (SCIMCoreConstants.LOCALITY.equals(kName)) {
                        addrTuple.setLocality(jParser.getString());
                    } else if (SCIMCoreConstants.REGION.equals(kName)) {
                        addrTuple.setRegion(jParser.getString());
                    } else if (SCIMCoreConstants.ZIPCODE.equals(kName)) {
                        addrTuple.setCode(jParser.getString());
                    } else if (SCIMCoreConstants.COUNTRY.equals(kName)) {
                        addrTuple.setCountry(jParser.getString());
                    } else if (SCIMCoreConstants.TYPE.equals(kName)) {
                        addrTuple.setType(jParser.getString());
                    } else {
                        throw new JsonParsingException("Wrong address format", jParser.getLocation());
                    }
                    kName = null;

                } else {
                    throw new JsonParsingException("Wrong address format", jParser.getLocation());
                }

            }

            user.addUserAddress(addrTuple);
            addrTuple = new AddrValueTuple();

        }
    }

    private static void checkName(JsonParser jParser, SCIM2User user)
        throws DataSourceException {

        String keyName = null;
        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_OBJECT; evn = jParser.next()) {

            if (evn == JsonParser.Event.KEY_NAME) {
                keyName = getKeyName(jParser);
                continue;
            }

            if (evn != JsonParser.Event.VALUE_STRING) {
                throw new JsonParsingException("Wrong meta attribute", jParser.getLocation());
            }

            try {
                if (SCIMCoreConstants.GIVEN_NAME.equals(keyName)) {
                    user.setUserGivenName(jParser.getString());
                } else if (SCIMCoreConstants.FAMILY_NAME.equals(keyName)) {
                    user.setUserFamilyName(jParser.getString());
                } else if (SCIMCoreConstants.MIDDLE_NAME.equals(keyName)) {
                    user.setUserMiddleName(jParser.getString());
                } else if (SCIMCoreConstants.HONORIFIC_PREFIX.equals(keyName)) {
                    user.setUserHonorPrefix(jParser.getString());
                } else if (SCIMCoreConstants.HONORIFIC_SUFFIX.equals(keyName)) {
                    user.setUserHonorSuffix(jParser.getString());
                }
            } catch (Exception ex) {
                throw new JsonParsingException(ex.getMessage(), jParser.getLocation());
            }

        }
    }

    public static SCIM2User decodeUser(String inStr)
        throws DataSourceException {

        JsonParser jParser = Json.createParser(new StringReader(inStr));
        SCIM2User result = new SCIM2User();
        Set<String> schemas = new HashSet<String>();
        String keyName = null;
        int oLevel = 0;

        try {

            while (jParser.hasNext()) {
                JsonParser.Event event = jParser.next();

                if (event == JsonParser.Event.KEY_NAME) {

                    keyName = getKeyName(jParser);

                } else if (event == JsonParser.Event.VALUE_STRING) {

                    checkAttribute(jParser, result, keyName, jParser.getString());
                    keyName = null;

                } else if (event == JsonParser.Event.START_OBJECT) {

                    if (SCIMCoreConstants.META.equals(keyName)) {
                        checkMeta(result, jParser);
                    } else if (SCIMCoreConstants.NAME.equals(keyName)) {
                        checkName(jParser, result);
                    } else if (oLevel > 0 && keyName != null) {
                        throw new JsonParsingException("Unrecognized attribute:  " + keyName, jParser.getLocation());
                    } else if (oLevel > 0 && keyName == null) {
                        throw new JsonParsingException("Unrecognized object", jParser.getLocation());
                    }

                    oLevel++;
                    keyName = null;

                } else if (event == JsonParser.Event.END_OBJECT) {

                    oLevel--;

                } else if (event == JsonParser.Event.START_ARRAY) {

                    if (SCIMCoreConstants.SCHEMAS.equals(keyName)) {
                        checkSchemas(jParser, schemas);
                    } else if (SCIMCoreConstants.ADDRESSES.equals(keyName)) {
                        checkAddresses(jParser, result);
                    } else if (SCIMCoreConstants.GROUPS.equals(keyName)) {

                    } else {
                        checkStdMultiValue(jParser, result, keyName);
                    }
                    keyName = null;

                }
            }

            if (!schemas.contains(SCIMCoreConstants.SCIM2_USER_SCHEMA)) {
                throw new DataSourceException("User schema not defined");
            }

        } finally {
            jParser.close();
        }

        return result;
    }

    public static SCIM2Group decodeGroup(String inStr)
        throws DataSourceException {

        JsonParser jParser = Json.createParser(new StringReader(inStr));
        SCIM2Group result = new SCIM2Group();
        Set<String> schemas = new HashSet<String>();
        String keyName = null;
        int oLevel = 0;

        try {

            while (jParser.hasNext()) {
                JsonParser.Event event = jParser.next();

                if (event == JsonParser.Event.KEY_NAME) {

                    keyName = getKeyName(jParser);

                } else if (event == JsonParser.Event.VALUE_STRING) {

                    checkAttribute(jParser, result, keyName, jParser.getString());

                } else if (event == JsonParser.Event.START_OBJECT) {

                    if (SCIMCoreConstants.META.equals(keyName)) {
                        checkMeta(result, jParser);
                    } else if (oLevel > 0 && keyName != null) {
                        throw new JsonParsingException("Unrecognized attribute:  " + keyName, jParser.getLocation());
                    } else if (oLevel > 0 && keyName == null) {
                        throw new JsonParsingException("Unrecognized object", jParser.getLocation());
                    }

                    oLevel++;
                    keyName = null;

                } else if (event == JsonParser.Event.START_ARRAY) {

                    if (SCIMCoreConstants.SCHEMAS.equals(keyName)) {
                        checkSchemas(jParser, schemas);
                    } else if (SCIMCoreConstants.MEMBERS.equals(keyName)) {

                    } else {
                        throw new JsonParsingException("Attribute not recognized " + keyName, jParser.getLocation());
                    }
                    keyName = null;

                }
            }

            if (!schemas.contains(SCIMCoreConstants.SCIM2_GROUP_SCHEMA)) {
                throw new DataSourceException("Group schema not defined");
            }

        } finally {
            jParser.close();
        }

        return result;
    }

}