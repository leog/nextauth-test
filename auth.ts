import NextAuth from "next-auth";
import "next-auth/jwt";
import GoogleProvider, { type GoogleProfile } from "next-auth/providers/google";
import { createStorage } from "unstorage";
import { UnstorageAdapter } from "@auth/unstorage-adapter";

const storage = createStorage();

export const { handlers, auth, signIn, signOut } = NextAuth({
  debug: !!process.env.AUTH_DEBUG,
  theme: { logo: "https://authjs.dev/img/logo-sm.png" },
  adapter: UnstorageAdapter(storage),
  events: {
    linkAccount: async ({ user }) => {
      console.log("authConfig:events:linkAccount", { user });
      if (user.id) {
        console.log("ACCOUNT LINKED", user.id, {
          emailVerified: new Date(),
        });
      }
    },
  },
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      authorization: {
        params: {
          scope:
            "openid email profile https://www.googleapis.com/auth/admin.directory.user.readonly",
        },
      },
      checks: ["none"],
      profile: async (profile: GoogleProfile, tokens) => {
        if (!profile.hd) {
          throw Error("Google Hosted Domain not allowed");
        }
        let adminData: Record<string, string> | null = null;
        try {
          if (tokens.access_token) {
            const response = await fetch(
              `https://admin.googleapis.com/admin/directory/v1/users/${profile.email}`,
              {
                method: "GET",
                headers: {
                  Authorization: `Bearer ${tokens.access_token}`,
                  Accept: "application/json",
                },
              },
            );

            if (!response.ok) {
              throw new Error(
                `Error fetching admin data: ${response.statusText}`,
              );
            }

            adminData = (await response.json()) as Record<string, string>;
          }
        } catch (error) {
          console.error("Error fetching admin directory data:", error);
        }

        return {
          firstName: profile.given_name,
          lastName: profile.family_name,
          email: profile.email,
          /*emailVerified: profile.email_verified ? new Date() : null, << DOESN'T WORK, events.linkAccount takes care of this */
          image: profile.picture,
          role: adminData?.isAdmin ? "ORGANIZATION_ADMIN" : "USER",
        };
      },
    }),
  ],
  basePath: "/auth",
  session: { strategy: "jwt" },
  callbacks: {
    authorized({ request, auth }) {
      const { pathname } = request.nextUrl;
      if (pathname === "/middleware-example") return !!auth;
      return true;
    },
    jwt({ token, trigger, session, account }) {
      if (trigger === "update") token.name = session.user.name;
      if (account?.provider === "keycloak") {
        return { ...token, accessToken: account.access_token };
      }
      return token;
    },
    async session({ session, token }) {
      if (token?.accessToken) session.accessToken = token.accessToken;

      return session;
    },
  },
  experimental: { enableWebAuthn: true },
});

declare module "next-auth" {
  interface Session {
    accessToken?: string;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string;
  }
}
