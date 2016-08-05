package grails.plugin.springsecurity.oauthprovider.serialization

import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import spock.lang.Specification

/**
 * Test serialize/deserialize
 */
class DefaultOAuth2AuthenticationSerializerSpec extends Specification {

    def serializer = new DefaultOAuth2AuthenticationSerializer()

    def 'authorization serialized and re-serialized is effectively the same'() {
        given: 'an authentication'
        def authentication = createTestOAuth2Authentication()

        and: 'the authentication is serialized'
        def serializedAuthentication = serializer.serialize(authentication)

        when: 'it is deserialized'
        def deserializedAuthentication = serializer.deserialize(serializedAuthentication)

        then: 'the objects are effectively the same'
        authentication == deserializedAuthentication
    }


    def 'serialized refreshed token does not grow unbound'() {
        given: 'an authentication'
        def authentication = createTestOAuth2Authentication()

        and: 'the authentication is refreshed'
        def refreshedAuthentication = simulateRefreshedAuthentication(authentication)

        and: 'the refreshed authentication is serialized'
        def refreshedOnceBytes = serializer.serialize(refreshedAuthentication) as byte[]

        and: 'another refresh'
        refreshedAuthentication = simulateRefreshedAuthentication(refreshedAuthentication)

        when: 'the re-refreshed authentication is serialized'
        def refreshedTwiceBytes = serializer.serialize(refreshedAuthentication) as byte[]

        then: 'the size of refreshing it once is the same as the size of refreshing it twice'
        refreshedOnceBytes.length == refreshedTwiceBytes.length

    }

    private static OAuth2Authentication createTestOAuth2Authentication() {
        def oauth2Request = new OAuth2Request(
                [
                        requestParam1: 'requestParam1',
                        requestParam2: 'requestParam2'
                ], // request parameters
                'test_client_id', // client id
                [new SimpleGrantedAuthority('ROLE_UNIT_TEST')], // authorities
                true, // approved
                ['test_scope'] as Set, // scope
                [] as Set, // resource ids
                null, // redirect uri
                ['application/json'] as Set, // response types
                null // extension properties
        )

        def userAuthentication = new TestingAuthenticationToken('test_user', 'test_password')

        new OAuth2Authentication(oauth2Request, userAuthentication)
    }

    private static OAuth2Authentication simulateRefreshedAuthentication(OAuth2Authentication authentication) {
        // refresh the client request
        def oauth2Request = authentication.getOAuth2Request()

        // since we're only simulating a request, just copy it into a new request
        def refreshedOauth2Request = oauth2Request.with {
            new OAuth2Request(
                requestParameters,
                clientId,
                authorities,
                approved,
                scope,
                resourceIds,
                redirectUri,
                responseTypes,
                extensions
        )}

        new OAuth2Authentication(refreshedOauth2Request, authentication.userAuthentication)
    }
}
