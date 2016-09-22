package it.infn.security.saml.iam.impl;

import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerException;

public class ChainIdentityManager
    implements IdentityManager {

    private static final Logger logger = Logger.getLogger(TLSIdentityManager.class.getName());

    private ArrayList<IdentityManager> managers;

    public ChainIdentityManager() {
        managers = new ArrayList<IdentityManager>();
    }

    public int getLoadPriority() {
        return 1;
    }

    public void init()
        throws IdentityManagerException {

        for (IdentityManager tmpMan : IdentityManager.identManagerLoader) {
            if (tmpMan.getLoadPriority() == 0) {
                managers.add(tmpMan);
                tmpMan.init();
                logger.info("Loaded identity manager: " + tmpMan.getClass().getCanonicalName());
            }
        }

        if (managers.size() == 0) {
            throw new IdentityManagerException("No identity manager in chain");
        }
    }

    public Subject authenticate()
        throws IdentityManagerException {

        for (IdentityManager tmpMan : managers) {
            try {
                return tmpMan.authenticate();
            } catch (IdentityManagerException idEx) {
                if (logger.getLevel().equals(Level.FINER)) {
                    logger.log(Level.FINER, idEx.getMessage(), idEx);
                } else {
                    logger.fine(idEx.getMessage());
                }
            }
        }

        throw new IdentityManagerException("User not authenticated");
    }

    public void close()
        throws IdentityManagerException {

        for (IdentityManager tmpMan : managers) {
            tmpMan.close();
        }

    }

}