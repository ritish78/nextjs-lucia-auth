import { Lucia } from "lucia";
import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
import db from "./db";
import { cookies } from "next/headers";

const adapter = new BetterSqlite3Adapter(db, {
  user: "users",
  session: "sessions",
});

const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === "production",
    },
  },
});

export async function createAuthSession(userId) {
  const session = await lucia.createSession(userId, {});
  const sessionCookie = lucia.createSessionCookie(session.id);

  cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
}

export async function verifyAuth() {
  const sessionCookie = cookies().get(lucia.sessionCookieName);

  //First, checking if the session cookie exists or not.
  if (!sessionCookie) {
    return {
      user: null,
      session: null,
    };
  }

  const sessionId = sessionCookie.value;
  //Then checking if sessionId exists inside the cookie.
  if (!sessionId) {
    return {
      user: null,
      session: null,
    };
  }

  //Then, we validate the sessionId
  const result = await lucia.validateSession(sessionId);

  try {
    if (result.session && result.session.true) {
      lucia.createSessionCookie(result.session.id);

      cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
    }

    if (!result.session) {
      const sessionCookie = lucia.createBlankSessionCookie();

      cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
    }
  } catch (error) {
    //We ignore the error. We add a try catch block because Nextjs
    //does not like when we set cookie when we render a page
  }

  return result;
}

export async function destroySession() {
  const { session } = await verifyAuth();

  if (!session) {
    return {
      error: "Unauthorized!",
    };
  }

  lucia.invalidateSession(session.id);

  const sessionCookie = lucia.createBlankSessionCookie();

  cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
}
