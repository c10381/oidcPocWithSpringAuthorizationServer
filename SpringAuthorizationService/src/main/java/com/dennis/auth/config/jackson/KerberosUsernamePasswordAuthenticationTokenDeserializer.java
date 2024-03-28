package com.dennis.auth.config.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.kerberos.authentication.JaasSubjectHolder;
import org.springframework.security.kerberos.authentication.KerberosUsernamePasswordAuthenticationToken;

import javax.security.auth.Subject;
import java.io.IOException;
import java.util.List;

public class KerberosUsernamePasswordAuthenticationTokenDeserializer extends JsonDeserializer<KerberosUsernamePasswordAuthenticationToken> {

    private static final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST = new TypeReference<>() {
    };

    private static final TypeReference<Object> OBJECT = new TypeReference<>() {
    };

    @Override
    public KerberosUsernamePasswordAuthenticationToken deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        ObjectMapper mapper = (ObjectMapper) p.getCodec();
        JsonNode jsonNode = mapper.readTree(p);
        Object principal = generatePrincipal(jsonNode, mapper);
        Object credentials = generateCredentials(jsonNode);
        List<GrantedAuthority> authorities = mapper.readValue(this.readJsonNode(jsonNode, "authorities").traverse(mapper), GRANTED_AUTHORITY_LIST);
        KerberosUsernamePasswordAuthenticationToken token = new KerberosUsernamePasswordAuthenticationToken(principal, credentials, authorities, new JaasSubjectHolder(new Subject()));
        token.setDetails(generateTokenDetails(jsonNode, mapper));
        return token;
    }

    private Object generatePrincipal(JsonNode jsonNode, ObjectMapper mapper) throws IOException {
        JsonNode principalNode = this.readJsonNode(jsonNode, "principal");
        return this.getPrincipal(mapper, principalNode);
    }

    private Object generateCredentials(JsonNode jsonNode) {
        JsonNode credentialsNode = this.readJsonNode(jsonNode, "credentials");
        return this.getCredentials(credentialsNode);
    }

    private Object generateTokenDetails(JsonNode jsonNode, ObjectMapper mapper) throws JsonProcessingException {
        JsonNode detailsNode = this.readJsonNode(jsonNode, "details");
        return !detailsNode.isNull() && !detailsNode.isMissingNode() ? mapper.readValue(detailsNode.toString(), OBJECT) : null;
    }

    private Object getCredentials(JsonNode credentialsNode) {
        return !credentialsNode.isNull() && !credentialsNode.isMissingNode() ? credentialsNode.asText() : null;
    }

    private Object getPrincipal(ObjectMapper mapper, JsonNode principalNode) throws IOException {
        return principalNode.isObject() ? mapper.readValue(principalNode.traverse(mapper), Object.class) : principalNode.asText();
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
