package com.dennis.auth.config.jackson;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@JsonTypeInfo(
        use = JsonTypeInfo.Id.CLASS,
        property = "@class"
)
@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE
)
@JsonDeserialize(
        using = KerberosUsernamePasswordAuthenticationTokenDeserializer.class
)
public abstract class KerberosUsernamePasswordAuthenticationTokenMixin {
    KerberosUsernamePasswordAuthenticationTokenMixin() {
    }
}