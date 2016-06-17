package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;

import java.io.StringReader;

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

    private static boolean checkResAttribute(SCIM2Resource resource, String kName, String value)
        throws DataSourceException {
        if ("id".equals(kName)) {
            resource.setResourceId(value);
            return true;
        }
        if ("externalId".equals(kName)) {
            resource.setResourceExtId(value);
            return true;
        }
        return false;
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

    private static boolean checkUserAttribute(SCIM2User user, String kName, String value)
        throws DataSourceException {
        if ("userName".equals(kName)) {
            user.setName(value);
            return true;
        }
        return false;
    }

    private static boolean checkUserAttribute(SCIM2User user, String kName, int value)
        throws DataSourceException {
        return false;
    }

    public static SCIM2User decodeUser(String inStr)
        throws DataSourceException {

        JsonParser jParser = Json.createParser(new StringReader(inStr));
        SCIM2User result = new SCIM2User();

        try {
            if (!jParser.hasNext() || jParser.next() != JsonParser.Event.START_OBJECT) {
                throw new JsonParsingException("Wrong json format", jParser.getLocation());
            }

            String keyName = null;

            while (jParser.hasNext()) {
                JsonParser.Event event = jParser.next();

                if (event == JsonParser.Event.KEY_NAME) {

                    keyName = getKeyName(jParser);

                } else if (event == JsonParser.Event.VALUE_STRING) {

                    String strValue = jParser.getString();
                    if (checkResAttribute(result, keyName, strValue) || checkUserAttribute(result, keyName, strValue)) {
                        keyName = null;
                    } else {
                        throw new RuntimeException("Wrong field " + keyName + " : " + strValue);
                    }

                } else if (event == JsonParser.Event.VALUE_NUMBER) {

                    int intValue = jParser.getInt();
                    if (checkUserAttribute(result, keyName, intValue)) {
                        keyName = null;
                    } else {
                        throw new RuntimeException("Wrong field " + keyName + " : " + intValue);
                    }

                } else if (event == JsonParser.Event.START_OBJECT) {

                    if ("meta".equals(keyName)) {
                        checkMeta(result, jParser);
                    }

                } else if (event == JsonParser.Event.START_ARRAY) {

                }
            }

            if (!jParser.hasNext() || jParser.next() != JsonParser.Event.START_OBJECT) {
                throw new JsonParsingException("Wrong json format", jParser.getLocation());
            }

        } finally {
            jParser.close();
        }

        return result;
    }
}