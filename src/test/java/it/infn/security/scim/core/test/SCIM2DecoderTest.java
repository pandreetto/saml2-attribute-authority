package it.infn.security.scim.core.test;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;

import it.infn.security.scim.core.SCIM2Decoder;
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

        StringBuffer jUser = new StringBuffer("{");

        jUser.append("\"schemas\" : [ \"urn:ietf:params:scim:schemas:core:2.0:User\" ], ");
        jUser.append("\"id\" : \"").append(id).append("\", ");

        jUser.append("\"meta\" : {");
        jUser.append("\"created\" : \"").append(dFormatter.format(cDate)).append("\", ");
        jUser.append("\"lastModified\" : \"").append(dFormatter.format(mDate)).append("\"");
        jUser.append("}, ");

        jUser.append("\"externalId\" : \"").append(extId).append("\"");

        jUser.append("}");

        try {

            SCIM2User user = SCIM2Decoder.decodeUser(jUser.toString());

            Assert.assertEquals("User ID", id, user.getResourceId());
            Assert.assertEquals("External ID", extId, user.getResourceExtId());
            Assert.assertEquals("Creation date", cDate, user.getResourceCreationDate());
            Assert.assertEquals("Modification date", mDate, user.getResourceChangeDate());

        } catch (Exception ex) {

            ex.printStackTrace();
            Assert.fail(ex.getMessage());

        }
    }
}
