package it.infn.security.saml.iam;

public class AccessManagerException
    extends Exception {

    public static final long serialVersionUID = 1432298722;

    public AccessManagerException() {
        super();
    }

    public AccessManagerException(String msg) {
        super(msg);
    }

    public AccessManagerException(String msg, Throwable th) {
        super(msg, th);
    }
}