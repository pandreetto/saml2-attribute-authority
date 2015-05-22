package it.infn.security.saml.iam;

public class IdentityManagerException
    extends Exception {

    public static final long serialVersionUID = 1432299159;

    public IdentityManagerException() {
        super();
    }

    public IdentityManagerException(String msg) {
        super(msg);
    }

    public IdentityManagerException(String msg, Throwable th) {
        super(msg, th);
    }
}