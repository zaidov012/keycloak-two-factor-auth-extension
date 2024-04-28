FROM quay.io/keycloak/keycloak:24.0.3
ADD target/two-factor-auth-rest-api.jar /opt/keycloak/providers/
