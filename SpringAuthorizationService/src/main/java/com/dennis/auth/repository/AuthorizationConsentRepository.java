package com.dennis.auth.repository;

import com.dennis.auth.model.AuthorizationConsent;
import com.dennis.auth.model.AuthorizationConsent.AuthorizationConsentId;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorizationConsentRepository extends JpaRepository<AuthorizationConsent, AuthorizationConsentId> {
  Optional<AuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
  void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}
