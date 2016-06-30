package it.infn.security.scim.core;

import it.infn.security.saml.datasource.AddrValueTuple;
import it.infn.security.saml.datasource.AttrValueTuple;
import it.infn.security.saml.datasource.DataSourceException;

import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.List;

import javax.json.Json;
import javax.json.stream.JsonGenerator;

public class SCIM2Encoder {

    private static void encodeResource(SCIM2Resource resource, JsonGenerator jGenerator)
        throws DataSourceException {

        SimpleDateFormat dFormatter = new SimpleDateFormat(SCIMCoreConstants.DATE_PATTERN);

        jGenerator.write(SCIMCoreConstants.ID, resource.getResourceId());

        String extId = resource.getResourceExtId();
        if (extId != null)
            jGenerator.write(SCIMCoreConstants.EXTERNAL_ID, extId);
        jGenerator.writeStartObject(SCIMCoreConstants.META);

        jGenerator.write(SCIMCoreConstants.CREATED, dFormatter.format(resource.getResourceCreationDate()));
        jGenerator.write(SCIMCoreConstants.MODIFIED, dFormatter.format(resource.getResourceChangeDate()));

        String version = resource.getResourceVersion();
        if (version != null)
            jGenerator.write(SCIMCoreConstants.VERSION, version);
        jGenerator.writeEnd();

    }

    private static void encodeMultiValue(String name, List<AttrValueTuple> attrList, JsonGenerator jGenerator)
        throws DataSourceException {

        if (attrList == null || attrList.size() == 0)
            return;

        jGenerator.writeStartArray(name);
        for (AttrValueTuple tuple : attrList) {
            jGenerator.writeStartObject();
            jGenerator.write(SCIMCoreConstants.VALUE, tuple.getValue());
            jGenerator.write(SCIMCoreConstants.TYPE, tuple.getType());
            jGenerator.writeEnd();
        }
        jGenerator.writeEnd();

    }

    public static String encodeUser(SCIM2User user)
        throws DataSourceException {

        StringWriter result = new StringWriter();
        JsonGenerator jGenerator = Json.createGenerator(result);

        jGenerator.writeStartObject();
        jGenerator.writeStartArray("schemas");
        jGenerator.write(SCIMCoreConstants.SCIM2_USER_SCHEMA);
        jGenerator.writeEnd();

        encodeResource(user, jGenerator);

        jGenerator.write(SCIMCoreConstants.USER_NAME, user.getName());

        String gName = user.getUserGivenName();
        String mName = user.getUserMiddleName();
        String fName = user.getUserFamilyName();
        String hPrefix = user.getUserHonorPrefix();
        String hSuffix = user.getUserHonorSuffix();
        if (gName != null || mName != null || fName != null) {
            jGenerator.writeStartObject(SCIMCoreConstants.NAME);
            if (gName != null)
                jGenerator.write(SCIMCoreConstants.GIVEN_NAME, gName);
            if (mName != null)
                jGenerator.write(SCIMCoreConstants.MIDDLE_NAME, mName);
            if (fName != null)
                jGenerator.write(SCIMCoreConstants.FAMILY_NAME, fName);
            if (hPrefix != null)
                jGenerator.write(SCIMCoreConstants.HONORIFIC_PREFIX, hPrefix);
            if (hSuffix != null)
                jGenerator.write(SCIMCoreConstants.HONORIFIC_SUFFIX, hSuffix);
            jGenerator.writeEnd();
        }

        String dName = user.getUserDisplayName();
        if (dName != null)
            jGenerator.write(SCIMCoreConstants.DISPLAY_NAME, dName);

        String nName = user.getUserNickName();
        if (nName != null)
            jGenerator.write(SCIMCoreConstants.DISPLAY_NAME, nName);

        String pUrl = user.getUserURL();
        if (pUrl != null)
            jGenerator.write(SCIMCoreConstants.PROFILE_URL, pUrl);

        String title = user.getUserTitle();
        if (title != null)
            jGenerator.write(SCIMCoreConstants.TITLE, title);

        String posType = user.getUserPosition();
        if (posType != null)
            jGenerator.write(SCIMCoreConstants.USER_TYPE, posType);

        String lang = user.getUserLang();
        if (lang != null)
            jGenerator.write(SCIMCoreConstants.PREFERRED_LANGUAGE, lang);

        String locale = user.getUserLocale();
        if (locale != null)
            jGenerator.write(SCIMCoreConstants.LOCALE, locale);

        String tz = user.getUserTimezone();
        if (tz != null)
            jGenerator.write(SCIMCoreConstants.TIME_ZONE, tz);

        String pwd = user.getUserPwd();
        if (pwd != null)
            jGenerator.write(SCIMCoreConstants.PASSWORD, pwd);

        encodeMultiValue(SCIMCoreConstants.EMAILS, user.getUserEmails(), jGenerator);

        encodeMultiValue(SCIMCoreConstants.PHONE_NUMBERS, user.getUserPhones(), jGenerator);

        encodeMultiValue(SCIMCoreConstants.IMS, user.getUserIMs(), jGenerator);

        encodeMultiValue(SCIMCoreConstants.PHOTOS, user.getUserPhotos(), jGenerator);

        encodeMultiValue(SCIMCoreConstants.ENTITLEMENTS, user.getUserEntitles(), jGenerator);

        encodeMultiValue(SCIMCoreConstants.ROLES, user.getUserRoles(), jGenerator);

        encodeMultiValue(SCIMCoreConstants.X509CERTIFICATES, user.getUserCertificates(), jGenerator);

        /*
         * TODO missing group
         */

        List<AddrValueTuple> addresses = user.getUserAddresses();
        if (addresses != null && addresses.size() > 0) {
            jGenerator.writeStartArray(SCIMCoreConstants.ADDRESSES);
            for (AddrValueTuple addr : addresses) {
                jGenerator.writeStartObject();
                jGenerator.write(SCIMCoreConstants.STREET, addr.getStreet());
                jGenerator.write(SCIMCoreConstants.LOCALITY, addr.getLocality());
                jGenerator.write(SCIMCoreConstants.REGION, addr.getRegion());
                jGenerator.write(SCIMCoreConstants.ZIPCODE, addr.getCode());
                jGenerator.write(SCIMCoreConstants.COUNTRY, addr.getCountry());
                jGenerator.writeEnd();
            }
            jGenerator.writeEnd();
        }

        jGenerator.writeEnd().close();

        return result.toString();
    }

    public static String encodeGroup(SCIM2Group group)
        throws DataSourceException {

        StringWriter result = new StringWriter();
        JsonGenerator jGenerator = Json.createGenerator(result);

        jGenerator.writeStartObject();
        jGenerator.writeStartArray("schemas");
        jGenerator.write(SCIMCoreConstants.SCIM2_GROUP_SCHEMA);
        jGenerator.writeEnd();

        encodeResource(group, jGenerator);

        jGenerator.write(SCIMCoreConstants.DISPLAY_NAME, group.getName());

        if (group.getAllMembers().size() > 0) {
            jGenerator.writeStartArray(SCIMCoreConstants.MEMBERS);

            List<String> members = group.getUMembers();
            for (String memberId : members) {
                jGenerator.writeStartObject();
                jGenerator.write(SCIMCoreConstants.VALUE, memberId);
                jGenerator.write(SCIMCoreConstants.TYPE, "User");
                jGenerator.writeEnd();
            }

            members = group.getGMembers();
            for (String memberId : members) {
                jGenerator.writeStartObject();
                jGenerator.write(SCIMCoreConstants.VALUE, memberId);
                jGenerator.write(SCIMCoreConstants.TYPE, "Group");
                jGenerator.writeEnd();
            }

            jGenerator.writeEnd();
        }

        jGenerator.writeEnd().close();

        return result.toString();
    }
}