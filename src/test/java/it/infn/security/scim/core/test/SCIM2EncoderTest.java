package it.infn.security.scim.core.test;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
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

            SCIM2User user = new SCIM2User();
            user.setResourceId(userId);
            user.setName(userLogin);
            user.setResourceCreationDate(now);

            String nowStr = dFormatter.format(now);
            String tPattern = "'{'\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],"
                    + "\"id\":\"{0}\",\"meta\":'{'\"created\":\"{1}\",\"lastModified\":\"{2}\"'}',"
                    + "\"userName\":\"{3}\"'}'";
            String tStr = MessageFormat.format(tPattern, userId, nowStr, nowStr, userLogin);

            String out = SCIM2Encoder.encodeUser(user);

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
                    + "\"id\":\"{0}\",\"meta\":'{'\"created\":\"{1}\",\"lastModified\":\"{2}\"'}',"
                    + "\"displayName\":\"{3}\"'}'";
            String tStr = MessageFormat.format(tPattern, groupId, nowStr, nowStr, groupName);

            String out = SCIM2Encoder.encodeGroup(group);

            Assert.assertEquals("Json user", tStr, out);

        } catch (Exception ex) {

            ex.printStackTrace();
            Assert.fail(ex.getMessage());

        }
    }

}