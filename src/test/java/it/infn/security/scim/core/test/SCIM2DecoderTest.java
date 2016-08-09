package it.infn.security.scim.core.test;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import it.infn.security.saml.datasource.AddrValueTuple;
import it.infn.security.saml.datasource.AttrValueTuple;
import it.infn.security.scim.core.SCIM2Decoder;
import it.infn.security.scim.core.SCIM2Group;
import it.infn.security.scim.core.SCIM2User;
import it.infn.security.scim.core.SCIMCoreConstants;

import org.junit.Assert;
import org.junit.Test;

public class SCIM2DecoderTest {

    @Test
    public void decodeUser() {

        SimpleDateFormat dFormatter = new SimpleDateFormat(SCIMCoreConstants.DATE_PATTERN);

        String id = UUID.randomUUID().toString();
        String extId = "external:id:00000";

        Date cDate = new Date((System.currentTimeMillis() / 1000) * 1000 - 60000);
        Date mDate = new Date((System.currentTimeMillis() / 1000) * 1000);

        String gName = "John";
        String fName = "Doe";

        String street = "100 Universal City Plaza";
        String locality = "Hollywood";
        String region = "CA";
        String code = "91608";
        String country = "USA";

        HashSet<String> emails = new HashSet<String>();
        emails.add("test@testdomain.net");
        emails.add("admin@mydomain.org");
        HashSet<String> phones = new HashSet<String>();
        phones.add("345626564");
        phones.add("098343126");

        StringBuffer jUser = new StringBuffer("{");

        jUser.append("\"schemas\" : [ \"urn:ietf:params:scim:schemas:core:2.0:User\" ], ");
        jUser.append("\"id\" : \"").append(id).append("\", ");

        jUser.append("\"meta\" : {");
        jUser.append("\"created\" : \"").append(dFormatter.format(cDate)).append("\", ");
        jUser.append("\"lastModified\" : \"").append(dFormatter.format(mDate)).append("\"");
        jUser.append("}, ");

        jUser.append("\"name\" : {");
        jUser.append("\"givenName\" : \"").append(gName).append("\", ");
        jUser.append("\"familyName\" : \"").append(fName).append("\"");
        jUser.append("}, ");

        jUser.append("\"externalId\" : \"").append(extId).append("\",");

        jUser.append("\"addresses\" : [ { ");
        jUser.append("\"streetAddress\" : \"").append(street).append("\", ");
        jUser.append("\"locality\" : \"").append(locality).append("\", ");
        jUser.append("\"region\" : \"").append(region).append("\", ");
        jUser.append("\"postalCode\" : \"").append(code).append("\", ");
        jUser.append("\"country\" : \"").append(country).append("\", ");
        jUser.append("\"type\" : \"work\" } ], ");

        jUser.append("\"emails\" : [");
        boolean start = true;
        for (String email : emails) {
            if (start) {
                start = false;
            } else {
                jUser.append(", ");
            }
            jUser.append("{ \"value\" : \"").append(email).append("\", \"type\" : \"work\" }");
        }
        jUser.append("], ");

        jUser.append("\"phoneNumbers\" : [");
        start = true;
        for (String phone : phones) {
            if (start) {
                start = false;
            } else {
                jUser.append(", ");
            }
            jUser.append("\"").append(phone).append("\"");
        }
        jUser.append("], ");

        jUser.append("\"groups\" : [ { \"value\" : \"54252...\", \"display\" : \"Test group\" } ]");

        jUser.append("}");

        try {

            SCIM2User user = SCIM2Decoder.decodeUser(jUser.toString());

            Assert.assertEquals("External ID", extId, user.getResourceExtId());

            Assert.assertEquals("Given name", gName, user.getUserGivenName());
            Assert.assertEquals("Family name", fName, user.getUserFamilyName());

            List<AttrValueTuple> uEmails = user.getUserEmails();
            if (uEmails == null || uEmails.size() != emails.size()) {
                Assert.fail("Cannot retrieve emails");
            }
            for (AttrValueTuple tuple : uEmails) {
                if (!emails.contains(tuple.getValue())) {
                    Assert.fail("Wrong email " + tuple.getValue());
                }
            }

            List<AttrValueTuple> uPhones = user.getUserPhones();
            if (uPhones == null || uPhones.size() != phones.size()) {
                Assert.fail("Cannot retrieve phones");
            }
            for (AttrValueTuple tuple : uPhones) {
                if (!phones.contains(tuple.getValue())) {
                    Assert.fail("Wrong phone " + tuple.getValue());
                }
            }

            List<AddrValueTuple> uAddresses = user.getUserAddresses();
            if (uAddresses == null || uAddresses.size() != 1) {
                Assert.fail("Cannot retrieve address");
            }
            AddrValueTuple uAddr = uAddresses.get(0);
            Assert.assertEquals("Street", street, uAddr.getStreet());
            Assert.assertEquals("Locality", locality, uAddr.getLocality());
            Assert.assertEquals("Region", region, uAddr.getRegion());
            Assert.assertEquals("Code", code, uAddr.getCode());
            Assert.assertEquals("Country", country, uAddr.getCountry());

        } catch (Exception ex) {

            ex.printStackTrace();
            Assert.fail(ex.getMessage());

        }
    }

    @Test
    public void decodeGroup() {

        SimpleDateFormat dFormatter = new SimpleDateFormat(SCIMCoreConstants.DATE_PATTERN);

        String id = UUID.randomUUID().toString();
        String extId = "external:id:00001";
        String dName = "Test group";

        Date cDate = new Date((System.currentTimeMillis() / 1000) * 1000 - 60000);
        Date mDate = new Date((System.currentTimeMillis() / 1000) * 1000);

        String uMember = "2819c223-7f76-453a-919d-413861904646";
        String gMember = "902c246b-6245-4190-8e05-00816be7344a";

        StringBuffer jGroup = new StringBuffer("{");

        jGroup.append("\"schemas\" : [ \"urn:ietf:params:scim:schemas:core:2.0:Group\" ], ");
        jGroup.append("\"id\" : \"").append(id).append("\", ");

        jGroup.append("\"meta\" : {");
        jGroup.append("\"created\" : \"").append(dFormatter.format(cDate)).append("\", ");
        jGroup.append("\"lastModified\" : \"").append(dFormatter.format(mDate)).append("\"");
        jGroup.append("}, ");

        jGroup.append("\"externalId\" : \"").append(extId).append("\",");

        jGroup.append("\"displayName\" : \"").append(dName).append("\",");

        jGroup.append("\"members\" : [");

        jGroup.append("{ \"value\" : \"").append(uMember).append("\", ");
        jGroup.append("\"$ref\" : \"https://example.com/v2/Users/");
        jGroup.append(uMember).append("\"}, ");

        jGroup.append("{ \"value\" : \"").append(gMember).append("\", ");
        jGroup.append("\"$ref\" : \"https://example.com/v2/Groups/");
        jGroup.append(gMember).append("\"}");

        jGroup.append("]}");

        try {

            SCIM2Group group = SCIM2Decoder.decodeGroup(jGroup.toString());

            Assert.assertEquals("External ID", extId, group.getResourceExtId());
            Assert.assertEquals("Display name", dName, group.getName());

            List<String> uMembers = group.getUMembers();
            Assert.assertTrue("User member", uMembers.get(0).endsWith(uMember));
            List<String> gMembers = group.getGMembers();
            Assert.assertTrue("Group member", gMembers.get(0).endsWith(gMember));

        } catch (Exception ex) {

            ex.printStackTrace();
            Assert.fail(ex.getMessage());

        }
    }
}
