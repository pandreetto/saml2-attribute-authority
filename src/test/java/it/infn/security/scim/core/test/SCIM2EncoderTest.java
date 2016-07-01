package it.infn.security.scim.core.test;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;

import it.infn.security.scim.core.SCIM2Encoder;
import it.infn.security.scim.core.SCIM2Group;
import it.infn.security.scim.core.SCIM2User;
import it.infn.security.scim.core.SCIMCoreConstants;

import org.junit.Assert;
import org.junit.Test;

public class SCIM2EncoderTest {

    @Test
    public void encodeUser() {

        try {

            SimpleDateFormat dFormatter = new SimpleDateFormat(SCIMCoreConstants.DATE_PATTERN);

            String userId = UUID.randomUUID().toString();
            String userLogin = "mylogin";
            Date now = new Date();

            String dgId = UUID.randomUUID().toString();
            String igId = UUID.randomUUID().toString();

            SCIM2User user = new SCIM2User();
            user.setResourceId(userId);
            user.setName(userLogin);
            user.setResourceCreationDate(now);

            String groupStr = "\"groups\":[";
            ArrayList<String> dGroup = new ArrayList<String>(1);
            dGroup.add(dgId);
            user.setLinkedResources(dGroup);
            groupStr += "{\"value\":\"" + dgId + "\",\"type\":\"direct\",\"$ref\":\"http://www.mysite.org/scim/Groups/"
                    + dgId + "\"},";
            ArrayList<String> uGroup = new ArrayList<String>(1);
            uGroup.add(igId);
            user.setAncestorResources(uGroup);
            groupStr += "{\"value\":\"" + igId
                    + "\",\"type\":\"indirect\",\"$ref\":\"http://www.mysite.org/scim/Groups/" + igId + "\"}";
            groupStr += "]";

            String nowStr = dFormatter.format(now);
            String tPattern = "'{'\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],"
                    + "\"id\":\"{0}\",\"meta\":'{'\"created\":\"{1}\",\"lastmodified\":\"{2}\"'}',"
                    + "\"username\":\"{3}\",{4}'}'";
            String tStr = MessageFormat.format(tPattern, userId, nowStr, nowStr, userLogin, groupStr);

            String out = SCIM2Encoder.encodeUser(user, "http://www.mysite.org/scim");

            Assert.assertEquals("Json user", tStr, out);

        } catch (Exception ex) {

            ex.printStackTrace();
            Assert.fail(ex.getMessage());

        }
    }

    @Test
    public void encodeGroup() {

        try {

            SimpleDateFormat dFormatter = new SimpleDateFormat(SCIMCoreConstants.DATE_PATTERN);

            String groupId = UUID.randomUUID().toString();
            String groupName = "mygroup";
            Date now = new Date();

            SCIM2Group group = new SCIM2Group();
            group.setResourceId(groupId);
            group.setName(groupName);
            group.setResourceCreationDate(now);

            String nowStr = dFormatter.format(now);
            String tPattern = "'{'\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],"
                    + "\"id\":\"{0}\",\"meta\":'{'\"created\":\"{1}\",\"lastmodified\":\"{2}\"'}',"
                    + "\"displayname\":\"{3}\"'}'";
            String tStr = MessageFormat.format(tPattern, groupId, nowStr, nowStr, groupName);

            String out = SCIM2Encoder.encodeGroup(group, "http://www.mysite.org/scim");

            Assert.assertEquals("Json user", tStr, out);

        } catch (Exception ex) {

            ex.printStackTrace();
            Assert.fail(ex.getMessage());

        }
    }

}