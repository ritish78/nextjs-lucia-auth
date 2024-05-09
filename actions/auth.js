"use server";

import { createAuthSession, destroySession } from "@/lib/auth";
import { hashPassword, verifyPassword } from "@/lib/hash";
import { createUser, getUserByEmail } from "@/lib/user";
import { redirect } from "next/navigation";

export async function signup(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");

  let errors = {};

  if (!email.includes("@")) {
    errors.email = "Please enter a valid email address!";
  }

  if (password.trim().length < 8) {
    errors.password = "Password must be atleast 8 characters long!";
  }

  if (Object.keys(errors).length > 0) {
    return {
      errors,
    };
  }

  //First, let's hash the password before storing in the db
  const hashedPassword = hashPassword(password);

  try {
    //If there are no errors then we create the account for the user
    const id = createUser(email, hashedPassword);

    await createAuthSession(id);
    redirect("/training");
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return {
        errors: {
          email: "Account already exists! Login instead!",
        },
      };
    }
    throw error;
  }
}

export async function login(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");

  //Query the user table against the supplied email
  const userByEmail = getUserByEmail(email);

  //If the user by email does not exists, we throw Invalid Credentials! error message
  if (!userByEmail) {
    return {
      errors: {
        error: "Invalid Credentials!",
      },
    };
  }

  //If the user exists, we then verify if the password supplied
  //during login is the same as the one set during signup.
  const passwordMatches = verifyPassword(password, userByEmail.password);

  //If password does not match, we throw the same Invalid Credentials! error message
  if (!passwordMatches) {
    return {
      errors: {
        error: "Invalid Credentials!",
      },
    };
  }

  //Finally, the user is verified and we then create session and can redirect the,
  await createAuthSession(userByEmail.id);
  redirect("/training");
}

export async function auth(mode, prevState, formData) {
  if (mode === "login") {
    return login(prevState, formData);
  } else {
    return signup(prevState, formData);
  }
}

export async function logout() {
  await destroySession();

  redirect("/");
}
