package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;

import java.io.StringReader;
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
        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_OBJECT; evn = jParser.next()) {
            /*
             * TODO can be ignored??
             */
            if (evn != JsonParser.Event.KEY_NAME && evn != JsonParser.Event.VALUE_STRING) {
                throw new JsonParsingException("Wrong meta attribute", jParser.getLocation());
            }
        }
    }

    private static void checkAttribute(JsonParser jParser, SCIM2User user, String kName, String value)
        throws DataSourceException {

        if (SCIMCoreConstants.USER_NAME.equals(kName)) {
            user.setName(value);
        } else if (SCIMCoreConstants.DISPLAY_NAME.equals(kName)) {

        } else if (SCIMCoreConstants.PROFILE_URL.equals(kName)) {

        } else if (SCIMCoreConstants.TITLE.equals(kName)) {

        } else if (SCIMCoreConstants.USER_TYPE.equals(kName)) {

        } else if (SCIMCoreConstants.PREFERRED_LANGUAGE.equals(kName)) {

        } else if (SCIMCoreConstants.LOCALE.equals(kName)) {

        } else if (SCIMCoreConstants.TIME_ZONE.equals(kName)) {

        } else if (SCIMCoreConstants.PASSWORD.equals(kName)) {

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

    private static void checkSubAttribute(JsonParser jParser, List<String[]> attrList) {

        String[] aTuple = new String[] { null, null };

        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_OBJECT; evn = jParser.next()) {
            String kName = null;

            if (evn == JsonParser.Event.KEY_NAME) {
                kName = jParser.getString();
            } else if (evn == JsonParser.Event.VALUE_STRING) {
                if (SCIMCoreConstants.VALUE.equals(kName)) {
                    aTuple[0] = jParser.getString();
                } else if (SCIMCoreConstants.PRIMARY.equals(kName)) {
                    // TODO ignored
                } else if (SCIMCoreConstants.TYPE.equals(kName)) {
                    aTuple[1] = jParser.getString();
                } else if (SCIMCoreConstants.DISPLAY.equals(kName)) {
                    // TODO ignored
                } else {
                    throw new JsonParsingException("Wrong subattribute format", jParser.getLocation());
                }
            } else {
                throw new JsonParsingException("Wrong subattribute format", jParser.getLocation());
            }
        }

        attrList.add(aTuple);
    }

    private static void checkStdMultiValue(JsonParser jParser, SCIM2User user, String kName)
        throws DataSourceException {

        List<String[]> attrList = new ArrayList<String[]>();

        for (JsonParser.Event evn = jParser.next(); evn != JsonParser.Event.END_ARRAY; evn = jParser.next()) {

            if (evn == JsonParser.Event.VALUE_STRING) {
                // primitive value
                attrList.add(new String[] { jParser.getString(), "undefined" });
            } else if (evn == JsonParser.Event.START_OBJECT) {
                // complex value
                checkSubAttribute(jParser, attrList);
            } else {
                throw new JsonParsingException("Wrong json format", jParser.getLocation());
            }
        }

        if (SCIMCoreConstants.EMAILS.equals(kName)) {
            for (String[] aTuple : attrList) {
                user.addUserEmail(aTuple[0], aTuple[1]);
            }
        } else if (SCIMCoreConstants.PHONE_NUMBERS.equals(kName)) {
            for (String[] aTuple : attrList) {
                user.addUserPhone(aTuple[0], aTuple[1]);
            }
        } else if (SCIMCoreConstants.IMS.equals(kName)) {
            for (String[] aTuple : attrList) {
                user.addUserIM(aTuple[0], aTuple[1]);
            }
        } else if (SCIMCoreConstants.PHOTOS.equals(kName)) {
            for (String[] aTuple : attrList) {
                user.addUserPhoto(aTuple[0], aTuple[1]);
            }
        } else if (SCIMCoreConstants.ENTITLEMENTS.equals(kName)) {
            for (String[] aTuple : attrList) {
                user.addUserEntitle(aTuple[0], aTuple[1]);
            }
        } else if (SCIMCoreConstants.ROLES.equals(kName)) {
            for (String[] aTuple : attrList) {
                user.addUserRole(aTuple[0], aTuple[1]);
            }
        } else if (SCIMCoreConstants.X509CERTIFICATES.equals(kName)) {
            for (String[] aTuple : attrList) {
                user.addUserCertificate(aTuple[0], aTuple[1]);
            }
        } else {
            throw new JsonParsingException("Attribute not recognized " + kName, jParser.getLocation());
        }
    }

    private static void checkBegin(JsonParser jParser) {
        if (!jParser.hasNext() || jParser.next() != JsonParser.Event.START_OBJECT) {
            throw new JsonParsingException("Wrong json format", jParser.getLocation());
        }
    }

    private static void checkEnd(JsonParser jParser) {
        if (!jParser.hasNext() || jParser.next() != JsonParser.Event.END_OBJECT) {
            throw new JsonParsingException("Wrong json format", jParser.getLocation());
        }
    }

    public static SCIM2User decodeUser(String inStr)
        throws DataSourceException {

        JsonParser jParser = Json.createParser(new StringReader(inStr));
        SCIM2User result = new SCIM2User();
        Set<String> schemas = new HashSet<String>();

        try {
            checkBegin(jParser);

            String keyName = null;

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

                    } else {
                        throw new JsonParsingException("Attribute not recognized " + keyName, jParser.getLocation());
                    }

                } else if (event == JsonParser.Event.START_ARRAY) {

                    if (SCIMCoreConstants.SCHEMAS.equals(keyName)) {
                        checkSchemas(jParser, schemas);
                    } else if (SCIMCoreConstants.ADDRESSES.equals(keyName)) {

                    } else if (SCIMCoreConstants.GROUPS.equals(keyName)) {

                    } else {
                        checkStdMultiValue(jParser, result, keyName);
                    }

                }
            }

            checkEnd(jParser);

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

        try {
            checkBegin(jParser);

            String keyName = null;

            while (jParser.hasNext()) {
                JsonParser.Event event = jParser.next();

                if (event == JsonParser.Event.KEY_NAME) {

                    keyName = getKeyName(jParser);

                } else if (event == JsonParser.Event.VALUE_STRING) {

                    checkAttribute(jParser, result, keyName, jParser.getString());

                } else if (event == JsonParser.Event.START_OBJECT) {

                    if (SCIMCoreConstants.META.equals(keyName)) {
                        checkMeta(result, jParser);
                    } else {
                        throw new JsonParsingException("Attribute not recognized " + keyName, jParser.getLocation());
                    }

                } else if (event == JsonParser.Event.START_ARRAY) {

                    if (SCIMCoreConstants.SCHEMAS.equals(keyName)) {
                        checkSchemas(jParser, schemas);
                    } else if (SCIMCoreConstants.MEMBERS.equals(keyName)) {

                    } else {
                        throw new JsonParsingException("Attribute not recognized " + keyName, jParser.getLocation());
                    }

                }
            }

            checkEnd(jParser);

            if (!schemas.contains(SCIMCoreConstants.SCIM2_GROUP_SCHEMA)) {
                throw new DataSourceException("Group schema not defined");
            }

        } finally {
            jParser.close();
        }

        return result;
    }

}