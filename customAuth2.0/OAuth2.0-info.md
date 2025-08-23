**Oauth2.0**:
- OAuth 2.0 is an authorization framework stands for **Open Authroization** that enables third-party applications to access protected resources on behalf of a user without requiring the user’s credentials. This is achieved through the use of access tokens, which are issued by an OAuth provider and used by third-party applications to access the user’s resources.
- OAuth 2.0 uses Access Tokens

**Overview of OAuth2.0**:
- OAuth 2.0 is an authorization protocol(Not an authentication protocol) that allows third-party applications to access resources on behalf of a user. It uses access tokens to provide access to resources, which are obtained after successful authentication. There are four roles in OAuth 2.0: Resource Owner, Client, Authorization Server, and Resource Server.
    - Resource Owner: The user who owns the resource that is being accessed by the client.
    - Client: The application that is requesting access to the resource on behalf of the user.
    - Authorization Server: The server that issues access tokens to the client after successful authentication of the user.
    - Resource Server: The server that holds the resource that is being accessed by the client.

**OAuth2.0 Flow**:
- User requests access to a protected resource from a third-party application.
- The third-party application redirects the user to an OAuth provider to obtain an access token.
- The user logs in to the OAuth provider and grants permission to the third-party application to access the protected resource.
- The OAuth provider issues an access token to the third-party application.
- The third-party application uses the access token to access the protected resource on behalf of the user.

**OAuth 2.0 Roles:**
- Resource Owner        : The user or system that owns the protected resources and can grant access to them
- Client                : Its a system that requires access to the protected resource with appropriate access token
- Authorization server  : It receives requests from the client for access tokens and issues them upon successful authentication and consent by the resource owner.
- Resource server       : A server that protects the user's resources and receives access request from the client and validates an Access token from the client and returns the appropriate resources to it.

**OAuth 2.0 Scopes:**
- Scopes are important concepts in OAuth 2.0.
- They are used to specify exactly the reason for which access to resources may be granted.