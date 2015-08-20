package it.infn.security.saml.datasource;

import java.util.ArrayList;
import java.util.List;

import org.wso2.charon.core.objects.User;

public class UserSearchResult {

    private int total;

    private List<User> users;

    public UserSearchResult() {
        total = 0;
        users = new ArrayList<User>();
    }
    
    public UserSearchResult(int initCap) {
        total = 0;
        users = new ArrayList<User>(initCap);
    }

    public void add(User user) {
        users.add(user);
    }

    public List<User> getUserList() {
        return users;
    }
    
    public boolean isEmpty() {
        return users.isEmpty();
    }

    public void setTotalResults(int tot) {
        total = tot;
    }

    public int getTotalResults() {
        return total;
    }
}