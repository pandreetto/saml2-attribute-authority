package it.infn.security.saml.iam;

import javax.security.auth.Subject;

import org.opensaml.saml2.core.AttributeQuery;

public class AccessManagerFactory {

    private static AccessManager manager = null;

    public static AccessManager getManager() {

        if (manager == null) {

            synchronized (AccessManagerFactory.class) {

                if (manager == null) {

                    manager = new AccessManager() {
                        public void init() {
                        }

                        public AccessConstraints authorizeAttributeQuery(Subject subject, AttributeQuery query) {
                            return new AccessConstraints();
                        }

                        public AccessConstraints authorizeCreateUser(Subject requester) {
                            return new AccessConstraints();
                        }

                        public AccessConstraints authorizeModifyUser(Subject requester, String userId) {
                            return new AccessConstraints();
                        }

                        public AccessConstraints authorizeDeleteUser(Subject requester, String userId) {
                            return new AccessConstraints();
                        }

                        public AccessConstraints authorizeShowUser(Subject requester, String userId) {
                            return new AccessConstraints();
                        }

                        public AccessConstraints authorizeListUsers(Subject requester) {
                            return new AccessConstraints();
                        }

                        public AccessConstraints authorizeCreateGroup(Subject requester) {
                            return new AccessConstraints();
                        }

                        public AccessConstraints authorizeModifyGroup(Subject requester, String groupId) {
                            return new AccessConstraints();
                        }

                        public AccessConstraints authorizeDeleteGroup(Subject requester, String groupId) {
                            return new AccessConstraints();
                        }

                        public AccessConstraints authorizeShowGroup(Subject requester, String groupId) {
                            return new AccessConstraints();
                        }

                        public AccessConstraints authorizeListGroups(Subject requester) {
                            return new AccessConstraints();
                        }

                        public void close() {
                        }
                    };

                }
            }
        }

        return manager;
    }
}