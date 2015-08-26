package it.infn.security.saml.iam;

import java.util.ServiceLoader;

import javax.security.auth.Subject;

public interface IdentityManager {

    public void init()
        throws IdentityManagerException;

    public Subject authenticate()
        throws IdentityManagerException;

    public void close()
        throws IdentityManagerException;

    public int getLoadPriority();

    public static ServiceLoader<IdentityManager> identManagerLoader = ServiceLoader.load(IdentityManager.class);

}