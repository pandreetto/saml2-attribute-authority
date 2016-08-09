package it.infn.security.scim.core;

import it.infn.security.saml.datasource.AddrValueTuple;
import it.infn.security.saml.datasource.AttrValueTuple;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupResource;
import it.infn.security.saml.datasource.GroupSearchResult;
import it.infn.security.saml.datasource.UserResource;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.ocp.SPIDSchemaManager;
import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeValueInterface;

import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.List;

import javax.json.Json;
import javax.json.stream.JsonGenerator;

public class SCIM2Encoder {

    private static void encodeResource(SCIM2Resource resource, String resUrl, JsonGenerator jGenerator)
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
        if (resUrl != null)
            jGenerator.write(SCIMCoreConstants.LOCATION, resUrl);

        jGenerator.writeEnd();

        encodeExtensions(resource, jGenerator);

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

    /*
     * TODO move into SPID package
     */
    private static void encodeExtensions(SCIM2Resource resource, JsonGenerator jGenerator)
        throws DataSourceException {
        Collection<AttributeEntry> extAttrs = resource.getExtendedAttributes();

        if (extAttrs == null || extAttrs.size() == 0)
            return;

        jGenerator.writeStartArray(SCIMCoreConstants.SPID_SCHEMA);
        for (AttributeEntry attr : extAttrs) {
            for (AttributeValueInterface attrVal : attr) {
                jGenerator.writeStartObject();
                jGenerator.write(SPIDSchemaManager.NAME_ATTR_ID, attr.getName().getNameId());
                jGenerator.write(SPIDSchemaManager.VALUE_ATTR_ID, attrVal.getValue().toString());
                jGenerator.writeEnd();
            }
        }
        jGenerator.writeEnd();

    }

    public static String encodeUser(SCIM2User user, String sitePrefix)
        throws DataSourceException {

        StringWriter result = new StringWriter();
        JsonGenerator jGenerator = Json.createGenerator(result);

        jGenerator.writeStartObject();
        jGenerator.writeStartArray(SCIMCoreConstants.SCHEMAS);
        jGenerator.write(SCIMCoreConstants.SCIM2_USER_SCHEMA);

        Collection<AttributeEntry> extAttrs = user.getExtendedAttributes();
        if (extAttrs != null && extAttrs.size() > 0) {
            jGenerator.write(SCIMCoreConstants.SPID_SCHEMA);
        }

        jGenerator.writeEnd();

        streamUser(user, sitePrefix, jGenerator);

        jGenerator.writeEnd().close();

        return result.toString();
    }

    private static void streamUser(SCIM2User user, String sitePrefix, JsonGenerator jGenerator)
        throws DataSourceException {

        String resUrl = sitePrefix + "/Users/" + user.getResourceId();
        encodeResource(user, resUrl, jGenerator);

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

        List<String> dGroup = user.getLinkedResources();
        List<String> uGroup = user.getAncestorResources();
        boolean showGroup = dGroup != null && uGroup != null && (dGroup.size() + uGroup.size()) > 0;
        if (showGroup) {
            jGenerator.writeStartArray(SCIMCoreConstants.GROUPS);
        }
        if (dGroup != null && dGroup.size() > 0) {
            for (String gId : dGroup) {
                jGenerator.writeStartObject().write(SCIMCoreConstants.VALUE, gId);
                jGenerator.write(SCIMCoreConstants.TYPE, "direct");
                jGenerator.write(SCIMCoreConstants.REF, sitePrefix + "/Groups/" + gId).writeEnd();
            }
        }
        if (uGroup != null && uGroup.size() > 0) {
            for (String gId : uGroup) {
                jGenerator.writeStartObject().write(SCIMCoreConstants.VALUE, gId);
                jGenerator.write(SCIMCoreConstants.TYPE, "indirect");
                jGenerator.write(SCIMCoreConstants.REF, sitePrefix + "/Groups/" + gId).writeEnd();
            }
        }
        if (showGroup) {
            jGenerator.writeEnd();
        }

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

    }

    public static String encodeUserList(UserSearchResult searchResult, String sitePrefix)
        throws DataSourceException {

        StringWriter result = new StringWriter();
        JsonGenerator jGenerator = Json.createGenerator(result);
        jGenerator.writeStartObject();

        jGenerator.writeStartArray(SCIMCoreConstants.SCHEMAS);
        jGenerator.write(SCIMCoreConstants.SCIM2_LIST_SCHEMA);
        jGenerator.writeEnd();

        if (searchResult == null || searchResult.isEmpty()) {
            jGenerator.write(SCIMCoreConstants.TOTAL_RESULTS, 0);
        } else {
            /*
             * TODO missing START_INDEX and ITEM_PER_PAGE
             */
            jGenerator.write(SCIMCoreConstants.TOTAL_RESULTS, searchResult.getTotalResults());
            jGenerator.writeStartArray(SCIMCoreConstants.RESOURCES);
            for (UserResource user : searchResult.getUserList()) {
                jGenerator.writeStartObject();
                streamUser((SCIM2User) user, sitePrefix, jGenerator);
                jGenerator.writeEnd();
            }
            jGenerator.writeEnd();
        }

        jGenerator.writeEnd().close();
        return result.toString();

    }

    public static String encodeGroup(SCIM2Group group, String sitePrefix)
        throws DataSourceException {

        StringWriter result = new StringWriter();
        JsonGenerator jGenerator = Json.createGenerator(result);

        jGenerator.writeStartObject();
        jGenerator.writeStartArray(SCIMCoreConstants.SCHEMAS);
        jGenerator.write(SCIMCoreConstants.SCIM2_GROUP_SCHEMA);

        Collection<AttributeEntry> extAttrs = group.getExtendedAttributes();
        if (extAttrs != null && extAttrs.size() > 0) {
            jGenerator.write(SCIMCoreConstants.SPID_SCHEMA);
        }

        jGenerator.writeEnd();

        streamGroup(group, sitePrefix, jGenerator);

        jGenerator.writeEnd().close();

        return result.toString();

    }

    private static void streamGroup(SCIM2Group group, String sitePrefix, JsonGenerator jGenerator)
        throws DataSourceException {

        String resUrl = sitePrefix + "/Groups/" + group.getResourceId();
        encodeResource(group, resUrl, jGenerator);

        jGenerator.write(SCIMCoreConstants.DISPLAY_NAME, group.getName());

        if (group.getAllMembers().size() > 0) {
            jGenerator.writeStartArray(SCIMCoreConstants.MEMBERS);

            List<String> members = group.getUMembers();
            for (String memberId : members) {
                jGenerator.writeStartObject();
                jGenerator.write(SCIMCoreConstants.VALUE, memberId);
                jGenerator.write(SCIMCoreConstants.REF, sitePrefix + "/Users/" + memberId);
                jGenerator.writeEnd();
            }

            members = group.getGMembers();
            for (String memberId : members) {
                jGenerator.writeStartObject();
                jGenerator.write(SCIMCoreConstants.VALUE, memberId);
                jGenerator.write(SCIMCoreConstants.REF, sitePrefix + "/Groups/" + memberId);
                jGenerator.writeEnd();
            }

            jGenerator.writeEnd();
        }

    }

    public static String encodeGroupList(GroupSearchResult searchResult, String sitePrefix)
        throws DataSourceException {

        StringWriter result = new StringWriter();
        JsonGenerator jGenerator = Json.createGenerator(result);
        jGenerator.writeStartObject();

        jGenerator.writeStartArray(SCIMCoreConstants.SCHEMAS);
        jGenerator.write(SCIMCoreConstants.SCIM2_LIST_SCHEMA);
        jGenerator.writeEnd();

        if (searchResult == null || searchResult.isEmpty()) {
            jGenerator.write(SCIMCoreConstants.TOTAL_RESULTS, 0);
        } else {
            /*
             * TODO missing START_INDEX and ITEM_PER_PAGE
             */
            jGenerator.write(SCIMCoreConstants.TOTAL_RESULTS, searchResult.getTotalResults());
            jGenerator.writeStartArray(SCIMCoreConstants.RESOURCES);
            for (GroupResource user : searchResult.getGroupList()) {
                jGenerator.writeStartObject();
                streamGroup((SCIM2Group) user, sitePrefix, jGenerator);
                jGenerator.writeEnd();
            }
            jGenerator.writeEnd();
        }

        jGenerator.writeEnd().close();
        return result.toString();

    }

    public static String encodeException(int code, String message) {

        StringWriter result = new StringWriter();
        JsonGenerator jGenerator = Json.createGenerator(result);
        jGenerator.writeStartObject();

        jGenerator.writeStartArray(SCIMCoreConstants.SCHEMAS);
        jGenerator.write(SCIMCoreConstants.SCIM2_ERR_SCHEMA);
        jGenerator.writeEnd();

        jGenerator.write(SCIMCoreConstants.STATUS, code);
        /*
         * TODO improve detail, see RFC7644 (3.12)
         */
        jGenerator.write(SCIMCoreConstants.DETAIL, message);

        jGenerator.writeEnd().close();
        return result.toString();

    }

}