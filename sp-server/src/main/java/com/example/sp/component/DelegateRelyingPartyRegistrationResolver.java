package com.example.sp.component;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

import static com.example.sp.config.SecurityConfiguration.DEFAULT_REGISTRATION_ID;

public final class DelegateRelyingPartyRegistrationResolver implements Converter<HttpServletRequest, RelyingPartyRegistration>, RelyingPartyRegistrationResolver {
    private final RelyingPartyRegistrationResolver origin;
    private boolean ignoreRegistrationId = false;
    private String defaultRegistrationId = DEFAULT_REGISTRATION_ID;

    public DelegateRelyingPartyRegistrationResolver(RelyingPartyRegistrationResolver origin) {
        Assert.notNull(origin, "Origin is null.");
        this.origin = origin;
    }

    @Override
    public RelyingPartyRegistration convert(HttpServletRequest source) {
        if (origin instanceof Converter) {
            return ((Converter<HttpServletRequest, RelyingPartyRegistration>) origin).convert(source);
        }
        throw new UnsupportedOperationException(origin.getClass() + " not implement Converter interface.");
    }

    @Override
    public RelyingPartyRegistration resolve(HttpServletRequest request, String relyingPartyRegistrationId) {
        if (ignoreRegistrationId) {
            return origin.resolve(request, defaultRegistrationId);
        }
        return origin.resolve(request, relyingPartyRegistrationId);
    }

    public boolean isIgnoreRegistrationId() {
        return ignoreRegistrationId;
    }

    public void setIgnoreRegistrationId(boolean ignoreRegistrationId) {
        this.ignoreRegistrationId = ignoreRegistrationId;
    }

    public String getDefaultRegistrationId() {
        return defaultRegistrationId;
    }

    public void setDefaultRegistrationId(String defaultRegistrationId) {
        this.defaultRegistrationId = defaultRegistrationId;
    }
}
