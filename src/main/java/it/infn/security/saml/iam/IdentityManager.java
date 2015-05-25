package it.infn.security.saml.iam;

import javax.security.auth.Subject;

public interface IdentityManager {
    
    public void init() throws IdentityManagerException;
    
    public Subject authenticate() throws IdentityManagerException;
    
    public void close() throws IdentityManagerException;
    
}