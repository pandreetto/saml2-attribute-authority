package it.infn.security.saml.utils;

import java.security.cert.X509Certificate;
import java.util.Set;

import javax.security.auth.Subject;

import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.x509.BasicX509Credential;

public class EncryptUtils {

    public static EncryptedAssertion encryptObject(SAMLObject object, Credential credential)
        throws EncryptionException {

        EncryptionParameters encParams = new EncryptionParameters();
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        KeyEncryptionParameters kEncParams = new KeyEncryptionParameters();
        kEncParams.setEncryptionCredential(credential);
        kEncParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        KeyInfoGeneratorFactory kigf = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager()
                .getDefaultManager().getFactory(credential);
        kEncParams.setKeyInfoGenerator(kigf.newInstance());

        Encrypter samlEncrypter = new Encrypter(encParams, kEncParams);
        samlEncrypter.setKeyPlacement(KeyPlacement.PEER);

        if (object instanceof Assertion) {
            return samlEncrypter.encrypt((Assertion) object);
        }

        throw new EncryptionException("Cannot encrypt object " + object.getClass().getName());
    }

    public static EncryptedAssertion encryptObject(SAMLObject object, X509Certificate cert)
        throws EncryptionException {

        BasicX509Credential x509Credential = new BasicX509Credential();
        x509Credential.setEntityCertificate(cert);

        return encryptObject(object, x509Credential);

    }

    public static EncryptedAssertion encryptObject(SAMLObject object, Subject subject)
        throws EncryptionException {

        Set<X509Certificate[]> allChains = subject.getPublicCredentials(X509Certificate[].class);

        if (allChains.size() == 0) {
            throw new EncryptionException("Cannot find certificate chain in subject");
        }

        X509Certificate[] certChain = allChains.iterator().next();

        return encryptObject(object, certChain[0]);
    }
}