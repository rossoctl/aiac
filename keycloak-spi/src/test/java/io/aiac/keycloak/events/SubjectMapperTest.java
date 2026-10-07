package io.aiac.keycloak.events;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SubjectMapperTest {

    @Test
    void clientCreatedMapsToServiceSubject() {
        Optional<String> subject =
                SubjectMapper.subjectFor(SubjectMapper.ResourceKind.CLIENT, "CREATE", "clients/abc-123");
        assertEquals(Optional.of("aiac.apply.service.abc-123"), subject);
    }

    @Test
    void clientUpdateIsDropped() {
        Optional<String> subject =
                SubjectMapper.subjectFor(SubjectMapper.ResourceKind.CLIENT, "UPDATE", "clients/abc-123");
        assertTrue(subject.isEmpty());
    }

    @Test
    void realmRoleCreatedMapsToRoleSubject() {
        Optional<String> subject =
                SubjectMapper.subjectFor(SubjectMapper.ResourceKind.REALM_ROLE, "CREATE", "roles/editor");
        assertEquals(Optional.of("aiac.apply.role.editor"), subject);
    }

    @Test
    void realmRoleUpdatedMapsToRoleSubject() {
        Optional<String> subject =
                SubjectMapper.subjectFor(SubjectMapper.ResourceKind.REALM_ROLE, "UPDATE", "roles/editor");
        assertEquals(Optional.of("aiac.apply.role.editor"), subject);
    }

    @Test
    void clientRoleCreatedMapsToRoleSubjectUsingTrailingSegment() {
        Optional<String> subject = SubjectMapper.subjectFor(SubjectMapper.ResourceKind.CLIENT_ROLE, "CREATE",
                "clients/abc-123/roles/writer");
        assertEquals(Optional.of("aiac.apply.role.writer"), subject);
    }

    @Test
    void dottedRealmRoleNameIsEncodedToASingleSubjectToken() {
        Optional<String> subject =
                SubjectMapper.subjectFor(SubjectMapper.ResourceKind.REALM_ROLE, "CREATE", "roles/team.admin");
        // "%2E" keeps "team.admin" as one NATS token so "aiac.apply.role.*" still matches it —
        // a literal "." would split it into two tokens and the consumer's filter would miss it.
        assertEquals(Optional.of("aiac.apply.role.team%2Eadmin"), subject);
    }

    @Test
    void roleNameWithReservedSubjectCharactersIsEncoded() {
        Optional<String> subject =
                SubjectMapper.subjectFor(SubjectMapper.ResourceKind.CLIENT_ROLE, "UPDATE", "clients/abc-123/roles/a*b>c d%e");
        assertEquals(Optional.of("aiac.apply.role.a%2Ab%3Ec%20d%25e"), subject);
    }

    @Test
    void roleNameWithTabCarriageReturnAndNewlineIsEncoded() {
        Optional<String> subject =
                SubjectMapper.subjectFor(SubjectMapper.ResourceKind.REALM_ROLE, "CREATE", "roles/a\tb\rc\nd");
        assertEquals(Optional.of("aiac.apply.role.a%09b%0Dc%0Ad"), subject);
    }

    @Test
    void realmRoleAssignToAUserIsAUserRealmRoleMapping() {
        // An agent's service account is a user too, so its role mapping has the same path.
        assertTrue(SubjectMapper.isUserRealmRoleMapping(
                SubjectMapper.ResourceKind.REALM_ROLE_MAPPING, "CREATE", "users/user-1/role-mappings/realm"));
    }

    @Test
    void realmRoleUnassignFromAUserIsAUserRealmRoleMapping() {
        assertTrue(SubjectMapper.isUserRealmRoleMapping(
                SubjectMapper.ResourceKind.REALM_ROLE_MAPPING, "DELETE", "users/user-1/role-mappings/realm"));
    }

    @Test
    void groupRealmRoleMappingIsNotAUserRealmRoleMapping() {
        // Known limit: a role that a user holds through a group is not a holder (R3), so a group
        // mapping is dropped.
        assertFalse(SubjectMapper.isUserRealmRoleMapping(
                SubjectMapper.ResourceKind.REALM_ROLE_MAPPING, "CREATE", "groups/group-1/role-mappings/realm"));
    }

    @Test
    void otherRoleMappingPathsAndOperationsAreNotAUserRealmRoleMapping() {
        SubjectMapper.ResourceKind mapping = SubjectMapper.ResourceKind.REALM_ROLE_MAPPING;
        assertFalse(SubjectMapper.isUserRealmRoleMapping(mapping, "UPDATE", "users/user-1/role-mappings/realm"));
        assertFalse(SubjectMapper.isUserRealmRoleMapping(mapping, null, "users/user-1/role-mappings/realm"));
        assertFalse(SubjectMapper.isUserRealmRoleMapping(mapping, "CREATE", "users//role-mappings/realm"));
        assertFalse(SubjectMapper.isUserRealmRoleMapping(
                mapping, "CREATE", "users/user-1/role-mappings/clients/client-1"));
        assertFalse(SubjectMapper.isUserRealmRoleMapping(mapping, "CREATE", "users/user-1/role-mappings"));
        assertFalse(SubjectMapper.isUserRealmRoleMapping(mapping, "CREATE", "users/user-1/role-mappings/realm/x"));
        assertFalse(SubjectMapper.isUserRealmRoleMapping(mapping, "CREATE", null));
    }

    @Test
    void otherResourceKindsAreNotAUserRealmRoleMapping() {
        String path = "users/user-1/role-mappings/realm";
        assertFalse(SubjectMapper.isUserRealmRoleMapping(SubjectMapper.ResourceKind.OTHER, "CREATE", path));
        assertFalse(SubjectMapper.isUserRealmRoleMapping(SubjectMapper.ResourceKind.REALM_ROLE, "CREATE", path));
        assertFalse(SubjectMapper.isUserRealmRoleMapping(null, "CREATE", path));
    }

    @Test
    void realmRoleMappingHasNoSingleSubject() {
        // The roles are in the representation, not in the path: see isUserRealmRoleMapping.
        Optional<String> subject = SubjectMapper.subjectFor(
                SubjectMapper.ResourceKind.REALM_ROLE_MAPPING, "CREATE", "users/user-1/role-mappings/realm");
        assertTrue(subject.isEmpty());
    }

    @Test
    void roleIdMapsToRoleMembersSubject() {
        Optional<String> subject = SubjectMapper.roleMembersSubject("6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b");
        assertEquals(Optional.of("aiac.apply.role-members.6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"), subject);
    }

    @Test
    void roleIdThatIsNotOneSubjectTokenGivesNoSubject() {
        // A Keycloak role id is a UUID. An id with '.', '*', '>' or whitespace is not one NATS token:
        // "aiac.apply.role-members.*" would not match it, and the publish could not read the id back
        // from the last segment of the subject.
        assertTrue(SubjectMapper.roleMembersSubject(null).isEmpty());
        assertTrue(SubjectMapper.roleMembersSubject("").isEmpty());
        assertTrue(SubjectMapper.roleMembersSubject("a.b").isEmpty());
        assertTrue(SubjectMapper.roleMembersSubject("a*").isEmpty());
        assertTrue(SubjectMapper.roleMembersSubject("a>").isEmpty());
        assertTrue(SubjectMapper.roleMembersSubject("a b").isEmpty());
        assertTrue(SubjectMapper.roleMembersSubject("a\tb").isEmpty());
    }

    @Test
    void otherResourceKindsAreDropped() {
        Optional<String> subject =
                SubjectMapper.subjectFor(SubjectMapper.ResourceKind.OTHER, "CREATE", "users/some-user");
        assertTrue(subject.isEmpty());
    }

    @Test
    void malformedResourcePathIsDroppedNotThrown() {
        Optional<String> subject =
                SubjectMapper.subjectFor(SubjectMapper.ResourceKind.CLIENT, "CREATE", "not-a-clients-path");
        assertTrue(subject.isEmpty());
    }

    @Test
    void nullResourcePathIsDroppedNotThrown() {
        Optional<String> subject = SubjectMapper.subjectFor(SubjectMapper.ResourceKind.CLIENT, "CREATE", null);
        assertTrue(subject.isEmpty());
    }

    @Test
    void payloadIsMinimalJsonWithId() {
        assertEquals("{\"id\":\"abc-123\"}", SubjectMapper.payloadFor("abc-123"));
    }

    @Test
    void payloadEscapesQuotesAndBackslashes() {
        // Without escaping, a quote or backslash in entityId would produce malformed or
        // injected JSON (e.g. a crafted id could inject extra fields into the payload).
        assertEquals("{\"id\":\"a\\\"b\\\\c\"}", SubjectMapper.payloadFor("a\"b\\c"));
    }

    @Test
    void payloadEscapesControlCharacters() {
        assertEquals("{\"id\":\"a\\nb\\u0001c\"}", SubjectMapper.payloadFor("a\nb\u0001c"));
    }
}
